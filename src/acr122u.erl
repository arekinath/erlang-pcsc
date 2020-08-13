%%
%% erlang NIF binding for libpcsc
%%
%% Copyright 2020 Alex Wilson <alex@uq.edu.au>, The University of Queensland
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

%% @doc A pcsc_apdu_transform implementation which handles proprietary APDU
%%      formats used by the ACR122(U) and compatible NFC readers.
%%
%% This includes control commands which can manage the buzzer and LEDs and
%% change parameters which are relevant with or without a card present. To
%% use these commands without requiring a card, use the <code>direct</code>
%% share mode (with empty protocols list).
%%
%% To use direct control commands you may need to enable PCSC/CCID "escape"
%% commands in the relevant driver configuration on your system.
%%
%% This module is based on documentation from ACS available online at:
%% <a href="https://www.acs.com.hk/en/download-manual/419/API-ACR122U-2.04.pdf">
%% https://www.acs.com.hk/en/download-manual/419/API-ACR122U-2.04.pdf
%% </a>
-module(acr122u).

-include("iso7816.hrl").
-include("nfc.hrl").

-behaviour(pcsc_apdu_transform).

-export([
    classify_emulated_atr/1
]).

-export([
    formats/0,
    init/1,
    begin_transaction/1,
    command/2,
    reply/2,
    end_transaction/1,
    terminate/1
]).

-export([
    direct_binary_cmd/2,
    success_fail_cmd/2,
    apdu_binary_cmd/2
]).

-export_type([command/0, reply/0]).

-type get_firmware_version_command() :: get_firmware_version.
%% Retrieves the firmware version.
-type get_firmware_version_reply() :: {ok, binary()} | {error, term()}.
%% Binary will contain an ASCII string like "ACR122U201".

-type get_ats_command() :: get_ats.
%% Retrieve an NFC card's Answer to Select (ATS) value.
-type get_ats_reply() :: {ok, binary()} | {error, term()}.

-type get_uid_command() :: get_uid.
%% Retrieve an NFC card's UID or serial number.
-type get_uid_reply() :: {ok, binary()} | {error, term()}.

-type set_auto_buzzer_command() :: {set_auto_buzzer, on | off}.
%% Set whether the reader will sound its buzzer automatically when an NFC card
%% is detected.
-type set_auto_buzzer_reply() :: ok | {error, term()}.

-type msec() :: integer().

-type led_buzzer_state() :: #{
    red => on | off, green => on | off,
    for => msec(), buzz => boolean()
    }.

-type led_buzzer_command() :: {led_buzzer, Repeats :: integer(),
    Initial :: led_buzzer_state(), Final :: led_buzzer_state()}.
%% Control the LEDs and buzzer on the reader. This command will induce a
%% repeating, alternating pattern between two states (initial and final),
%% and then leave the LED and buzzer in the "final" state.
%%
%% For example, to make the red LED turn on and stay on, use:
%% <pre>
%%   {led_buzzer, 1, #{}, #{red => on}}
%% </pre>
%%
%% To make the red LED blink on and off 3 times at 200ms intervals, and then
%% stay off at the end, use:
%% <pre>
%%   {led_buzzer, 3, #{red => on, for => 200}, #{red => off, for => 200}}
%% </pre>
%%
%% To make the green LED flash once for 200ms and sound the buzzer, then turn
%% off and stay off, use:
%% <pre>
%%   {led_buzzer, 1, #{green => on, buzz => true, for => 200}, #{green => off}}
%% </pre>
-type led_buzzer_reply() :: ok | {error, term()}.

-type command() ::
    get_firmware_version_command() |
    get_ats_command() |
    get_uid_command() |
    set_auto_buzzer_command() |
    led_buzzer_command() |
    iso7816:apdu_cmd().

-type reply() ::
    get_firmware_version_reply() |
    get_ats_reply() |
    get_uid_reply() |
    set_auto_buzzer_reply() |
    led_buzzer_reply() |
    iso7816:apdu_reply().

-type mifare_subtype() :: mifare1k | mifare4k | ultralight | mini.
-type felica_subtype() :: felica212k | felica424k.

%% @doc Takes a decoded ATR and classifies whether it is one of the "emulated"
%% card types which does not accept ISO7816 APDUs (but the ACR122U will
%% translate certain APDUs for us).
-spec classify_emulated_atr(iso7816:atr_info()) -> not_emulated | unknown |
    {mifare, mifare_subtype()} | topaz_jewel | {felica, felica_subtype()}.
classify_emulated_atr(#{
            aid := <<16#A0, 0, 0, 3, 6, 3, CardName:2/binary, _/binary>>}) ->
    case CardName of
        <<16#00, 16#01>> -> {mifare, mifare1k};
        <<16#00, 16#02>> -> {mifare, mifare4k};
        <<16#00, 16#03>> -> {mifare, ultralight};
        <<16#00, 16#26>> -> {mifare, mini};
        <<16#F0, 16#04>> -> topaz_jewel;
        <<16#F0, 16#11>> -> {felica, felica212k};
        <<16#F0, 16#12>> -> {felica, felica424k};
        _ -> unknown
    end;
classify_emulated_atr(#{}) -> not_emulated.

%% @headerfile "nfc.hrl"

-record(?MODULE, {
    state = idle :: idle | passthrough | direct_binary_cmd | success_fail_cmd |
                    apdu_binary_cmd
}).

%% @private
formats() -> {
    [xapdu, apdu, acr122u],
    [xapdu, apdu, binary]
}.

%% @private
init(_Proto) ->
    {ok, #?MODULE{}}.

%% @private
terminate(#?MODULE{}) ->
    ok.

%% @private
begin_transaction(S = #?MODULE{}) ->
    {ok, S}.

%% @private
end_transaction(S = #?MODULE{}) ->
    {ok, S}.

%% @private
command(A0 = #apdu_cmd{}, S0 = #?MODULE{state = idle}) ->
    {ok, [A0], S0#?MODULE{state = passthrough}};

command(get_firmware_version, S0 = #?MODULE{state = idle}) ->
    A = #apdu_cmd{proto = direct,
        cla = 16#FF, ins = 16#00, p1 = 16#48, p2 = 16#00, le = 16#00},
    {ok, [A], S0#?MODULE{state = direct_binary_cmd}};

command(get_ats, S0 = #?MODULE{state = idle}) ->
    A = #apdu_cmd{
        cla = 16#FF, ins = 16#CA, p1 = 16#01, p2 = 16#00, le = 16#00},
    {ok, [A], S0#?MODULE{state = apdu_binary_cmd}};

command(get_uid, S0 = #?MODULE{state = idle}) ->
    A = #apdu_cmd{
        cla = 16#FF, ins = 16#CA, p1 = 16#00, p2 = 16#00, le = 16#00},
    {ok, [A], S0#?MODULE{state = apdu_binary_cmd}};

command({set_auto_buzzer, Mode}, S0 = #?MODULE{state = idle}) ->
    P2 = case Mode of
        on -> 16#FF;
        off -> 16#00
    end,
    A = #apdu_cmd{proto = direct,
        cla = 16#FF, ins = 16#00, p1 = 16#52, p2 = P2, le = 16#00},
    {ok, [A], S0#?MODULE{state = success_fail_cmd}};

command({led_buzzer, Repeats, Initial, Final}, S0 = #?MODULE{state = idle}) ->
    FinalRed = case Final of #{red := on} -> 1; _ -> 0 end,
    FinalGreen = case Final of #{green := on} -> 1; _ -> 0 end,
    FinalRedChange = case Final of #{red := _} -> 1; _ -> 0 end,
    FinalGreenChange = case Final of #{green := _} -> 1; _ -> 0 end,

    InitialRed = case Initial of #{red := on} -> 1; _ -> 0 end,
    InitialGreen = case Initial of #{green := on} -> 1; _ -> 0 end,
    InitialRedChange = case Initial of #{red := _} -> 1; _ -> 0 end,
    InitialGreenChange = case Initial of #{green := _} -> 1; _ -> 0 end,

    T1 = case Initial of #{for := T} -> T div 100; _ -> 0 end,
    T2 = case Final of #{for := TT} -> TT div 100; _ -> 0 end,

    BuzzerLink = case {Initial, Final} of
        {#{buzz := true}, _} -> 1;
        {_, #{buzz := true}} -> 2;
        {_, _} -> 0
    end,

    <<P2>> = <<InitialGreenChange:1, InitialRedChange:1, InitialGreen:1,
        InitialRed:1, FinalGreenChange:1, FinalRedChange:1, FinalGreen:1,
        FinalRed:1>>,
    Data = <<T1, T2, Repeats, BuzzerLink>>,

    A = #apdu_cmd{proto = direct,
        cla = 16#FF, ins = 16#00, p1 = 16#40, p2 = P2, data = Data},
    {ok, [A], S0#?MODULE{state = success_fail_cmd}}.

%% @private
reply(R0 = #apdu_reply{}, S0 = #?MODULE{state = passthrough}) ->
    {ok, [R0], S0#?MODULE{state = idle}};

reply(R0, S0 = #?MODULE{state = State}) ->
    ?MODULE:State(R0, S0).

%% @private
direct_binary_cmd({direct, Ver}, S0 = #?MODULE{}) ->
    {ok, [{ok, Ver}], S0#?MODULE{state = idle}};
direct_binary_cmd(#apdu_reply{sw = Err}, S0 = #?MODULE{}) ->
    {ok, [Err], S0#?MODULE{state = idle}}.

%% @private
success_fail_cmd({direct, <<16#90, 16#00>>}, S0 = #?MODULE{}) ->
    {ok, [ok], S0#?MODULE{state = idle}};
success_fail_cmd({direct, <<16#63, 16#00>>}, S0 = #?MODULE{}) ->
    {ok, [{error, failed}], S0#?MODULE{state = idle}}.

%% @private
apdu_binary_cmd(#apdu_reply{sw = ok, data = D}, S0 = #?MODULE{}) ->
    {ok, [{ok, D}], S0#?MODULE{state = idle}};
apdu_binary_cmd(#apdu_reply{sw = Err}, S0 = #?MODULE{}) ->
    {ok, [Err], S0#?MODULE{state = idle}}.
