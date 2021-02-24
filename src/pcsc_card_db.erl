%%
%% erlang NIF binding for libpcsc
%%
%% Copyright 2021 Alex Wilson <alex@uq.edu.au>, The University of Queensland
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

%% @doc Tracks the available readers and cards on the system, providing
%%      functions for listing the current state as well as subscribing to
%%      changes.
%%
%% <h3>Example</h3>
%% <pre>
%%   1> pcsc_card_db:list_readers().
%%   {ok,[&lt;&lt;"Yubico YubiKey OTP+FIDO+CCID 00 00">>,
%%        &lt;&lt;"Alcor Micro AU9560 01 00">>,
%%        &lt;&lt;"ACS ACR122U PICC Interface 02 00">>]}
%%
%%   2> pcsc_card_db:get_reader_state(&lt;&lt;"ACS ACR122U PICC Interface 02 00">>).
%%   {ok,[empty]}
%%
%%   3> pcsc_card_db:monitor_cards(#{in_reader => #{name_contains => &lt;&lt;"ACS">>}}).
%%   {ok,#Ref&lt;0.2854622174.861143041.134395>}
%%
%%   4> flush().
%%   ok
%%   5> flush().
%%   Shell got {pcsc_card,inserted,#Ref&lt;0.2854622174.861143041.134395>,
%%                        &lt;&lt;"ACS ACR122U PICC Interface 02 00">>,
%%                        &lt;&lt;59,129,128,1,128,128>>}
%%   ok
%%   6> flush().
%%   Shell got {pcsc_card,removed,#Ref&lt;0.2854622174.861143041.134395>,
%%                        &lt;&lt;"ACS ACR122U PICC Interface 02 00">>}
%%   ok
%% </pre>
-module(pcsc_card_db).

-behaviour(gen_server).

-compile([{parse_transform, lager_transform}]).

-export([
    start_link/0,
    list_readers/0,
    get_reader_state/1,
    get_reader_atr/1,
    list_cards/0,
    monitor_readers/1,
    demonitor_readers/1,
    monitor_cards/1,
    demonitor_cards/1
]).

-export([
    init/1, terminate/2,
    handle_call/3, handle_info/2, handle_cast/2
]).

-export_type([reader_filter/0, card_filter/0, card_monitor_msg/0,
    reader_monitor_msg/0]).

-type reader_filter() :: #{
    name => binary(),
    name_prefix => binary(),
    name_contains => binary()
}. %%
%% A filter for selecting which readers to receive events about.

-type card_filter() :: #{
    atr => binary(),
    atr_prefix => binary(),
    atr_contains => binary(),
    in_reader => reader_filter()
}. %%
%% A filter for selecting which cards to receive events about.

-type card_monitor_msg() ::
    {pcsc_card, inserted, reference(), RdrName :: binary(), ATR :: binary()} |
    {pcsc_card, removed, reference(), RdrName :: binary()}.
%% Messages sent to a subscriber who has called monitor_cards() when a card is
%% inserted or removed on the system.

-type reader_monitor_msg() ::
    {pcsc_reader, available | unavailable, reference(), RdrName :: binary()}.
%% Messages sent to a subscriber who has called monitor_readers() when a
%% card reader becomes available or ceases to be.

%% @private
% Will be created by pcsc_sup
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Returns the current list of card readers on the system, whether they
%%      contain a card or not.
-spec list_readers() -> {ok, [pcsc:rdrname()]} | {error, term()}.
list_readers() ->
    gen_server:call(?MODULE, list_readers).

%% @doc Retrieves the last known status of a particular card reader, including
%%      whether it has a card inserted and whether it is busy.
-spec get_reader_state(pcsc:rdrname()) -> {ok, [pcsc:rdrstate()]} | {error, term()}.
get_reader_state(RdrName) ->
    case gen_server:call(?MODULE, {get_state_atr, RdrName}) of
        {ok, St, _ATR} -> {ok, St};
        Err -> Err
    end.

%% @doc Retrieves the last known ATR sent by a card in a particular card reader.
-spec get_reader_atr(pcsc:rdrname()) -> {ok, binary()} | {error, term()}.
get_reader_atr(RdrName) ->
    case gen_server:call(?MODULE, {get_state_atr, RdrName}) of
        {ok, _St, ATR} -> {ok, ATR};
        Err -> Err
    end.

%% @doc Lists available cards on the system, with their reader names and ATRs.
-spec list_cards() -> {ok, [{pcsc:rdrname(), ATR :: binary()}]} | {error, term()}.
list_cards() ->
    gen_server:call(?MODULE, list_cards).

%% @doc Subscribes the calling process to notifications about changes to the
%%      set of available readers on the system. Messages received by callers
%%      are of the type <code>reader_monitor_msg()</code>. Returns a reference
%%      value which can be used to identify messages sent by this subscription
%%      and also useful with <code>demonitor_readers/1</code>
-spec monitor_readers(reader_filter()) -> {ok, reference()} | {error, term()}.
monitor_readers(Filter) ->
    gen_server:call(?MODULE, {monitor_readers, self(), Filter}).

%% @doc Subscribes the calling process to notifications about changes to the
%%      set of available cards on the system. Messages received by callers
%%      are of the type <code>card_monitor_msg()</code>. Returns a reference
%%      value which can be used to identify messages sent by this subscription
%%      and also useful with <code>demonitor_cards/1</code>
-spec monitor_cards(card_filter()) -> {ok, reference()} | {error, term()}.
monitor_cards(Filter) ->
    gen_server:call(?MODULE, {monitor_cards, self(), Filter}).

%% @doc Cancels a subscription set up by a call to <code>monitor_readers/1</code>.
-spec demonitor_readers(reference()) -> ok | {error, term()}.
demonitor_readers(Ref) ->
    gen_server:call(?MODULE, {demonitor_readers, Ref}).

%% @doc Cancels a subscription set up by a call to <code>monitor_cards/1</code>.
-spec demonitor_cards(reference()) -> ok | {error, term()}.
demonitor_cards(Ref) ->
    gen_server:call(?MODULE, {demonitor_cards, Ref}).

-record(rdrstate, {
    last_state :: [pcsc:rdrstate()],
    last_atr :: binary()
}).

-record(?MODULE, {
    ctx :: pcsc_nif:context(),
    msgref :: pcsc_nif:msgref(),
    readers = #{} :: #{pcsc:rdrname() => #rdrstate{}},
    monitors = #{} :: #{reference() => reference()},
    moninvs = #{} :: #{reference() => reference()},
    reader_mons = #{} :: #{reference() => {pid(), reader_filter()}},
    card_mons = #{} :: #{reference() => {pid(), card_filter()}}
}).

%% @private
init([]) ->
    case pcsc_nif:new_context() of
        {ok, Ctx, MsgRef} ->
            {ok, #?MODULE{ctx = Ctx, msgref = MsgRef}};
        {error, Err = {pcsc_error, _, Code, _}} when
                        (Code =:= no_service) or (Code =:= no_readers) ->
            FakeMsgRef = make_ref(),
            timer:send_after(1000, {pcsc_reader_error, FakeMsgRef, Err}),
            {ok, #?MODULE{msgref = FakeMsgRef}};
        Err ->
            lager:warning("pcsc_card_db failed to start: ~p", [Err]),
            {stop, Err}
    end.

%% @private
terminate(_Why, #?MODULE{}) -> ok.

%% @private
handle_call(list_readers, From, S0 = #?MODULE{readers = Rdrs0}) ->
    ReaderList = maps:fold(fun (Rdr, #rdrstate{last_state = St}, Acc) ->
        case is_reader_nonexistent(St) of
            false -> [Rdr | Acc];
            _ -> Acc
        end
    end, [], Rdrs0),
    gen_server:reply(From, {ok, ReaderList}),
    {noreply, S0};

handle_call({get_state_atr, RdrName}, From, S0 = #?MODULE{readers = Rdrs0}) ->
    case Rdrs0 of
        #{RdrName := #rdrstate{last_state = St, last_atr = ATR}} ->
            gen_server:reply(From, {ok, St, ATR});
        _ ->
            gen_server:reply(From, {error, not_found})
    end,
    {noreply, S0};

handle_call(list_cards, From, S0 = #?MODULE{readers = Rdrs0}) ->
    CardList = maps:fold(fun
        (Rdr, #rdrstate{last_state = St, last_atr = ATR}, Acc) ->
            case is_card_present(St) of
                true -> [{Rdr, ATR} | Acc];
                _ -> Acc
            end
    end, [], Rdrs0),
    gen_server:reply(From, {ok, CardList}),
    {noreply, S0};

handle_call({monitor_cards, Pid, Filter}, From,
        S0 = #?MODULE{readers = Rdrs0, monitors = Mons0, moninvs = Invs0,
                      card_mons = CMons0}) ->
    ClientRef = make_ref(),
    MonRef = erlang:monitor(process, Pid),
    Mons1 = Mons0#{MonRef => ClientRef},
    Invs1 = Invs0#{ClientRef => MonRef},
    CMons1 = CMons0#{ClientRef => {Pid, Filter}},
    S1 = S0#?MODULE{monitors = Mons1, moninvs = Invs1, card_mons = CMons1},
    gen_server:reply(From, {ok, ClientRef}),
    lists:foreach(fun
        ({Rdr, #rdrstate{last_state = St, last_atr = ATR}}) ->
            case is_card_present(St) of
                true ->
                    case card_matches_filter(Rdr, ATR, Filter) of
                        true ->
                            Pid ! {pcsc_card, inserted, ClientRef, Rdr, ATR};
                        false -> ok
                    end;
                _ -> ok
            end
    end, maps:to_list(Rdrs0)),
    {noreply, S1};

handle_call({monitor_readers, Pid, Filter}, From,
        S0 = #?MODULE{readers = Rdrs0, monitors = Mons0, reader_mons = RMons0,
                      moninvs = Invs0}) ->
    ClientRef = make_ref(),
    MonRef = erlang:monitor(process, Pid),
    Mons1 = Mons0#{MonRef => ClientRef},
    Invs1 = Invs0#{ClientRef => MonRef},
    RMons1 = RMons0#{ClientRef => {Pid, Filter}},
    S1 = S0#?MODULE{monitors = Mons1, moninvs = Invs1, reader_mons = RMons1},
    gen_server:reply(From, {ok, ClientRef}),
    lists:foreach(fun
        ({Rdr, #rdrstate{last_state = St}}) ->
            NonExistent = is_reader_nonexistent(St),
            Matches = reader_matches_filter(Rdr, Filter),
            case {NonExistent, Matches} of
                {false, true} ->
                    Pid ! {pcsc_reader, available, ClientRef, Rdr};
                _ -> ok
            end
    end, maps:to_list(Rdrs0)),
    {noreply, S1};

handle_call({demonitor_cards, Ref}, _From, S0 = #?MODULE{monitors = Mons0,
                                                         moninvs = Invs0,
                                                         card_mons = CMons0}) ->
    case Invs0 of
        #{Ref := MonRef} ->
            true = erlang:demonitor(MonRef),
            Mons1 = maps:remove(MonRef, Mons0),
            Invs1 = maps:remove(Ref, Invs0),
            CMons1 = maps:remove(Ref, CMons0),
            S1 = S0#?MODULE{monitors = Mons1, moninvs = Invs1,
                            card_mons = CMons1},
            {reply, ok, S1};
        _ ->
            {reply, {error, not_found}, S0}
    end;

handle_call({demonitor_readers, Ref}, _From, S0 = #?MODULE{monitors = Mons0,
                                                           reader_mons = RMons0,
                                                           moninvs = Invs0}) ->
    case Invs0 of
        #{Ref := MonRef} ->
            true = erlang:demonitor(MonRef),
            Mons1 = maps:remove(MonRef, Mons0),
            Invs1 = maps:remove(Ref, Invs0),
            RMons1 = maps:remove(Ref, RMons0),
            S1 = S0#?MODULE{monitors = Mons1, moninvs = Invs1,
                            reader_mons = RMons1},
            {reply, ok, S1};
        _ ->
            {reply, {error, not_found}, S0}
    end.

is_reader_nonexistent(Flags) ->
    lists:member(unknown, Flags) orelse lists:member(unavailable, Flags).
is_card_present(Flags) ->
    lists:member(present, Flags) andalso (not (
        is_reader_nonexistent(Flags) orelse lists:member(mute, Flags))).

%% @private
handle_info({pcsc_reader, MsgRef, RdrName, Evts, ATR},
        S0 = #?MODULE{msgref = MsgRef, readers = Rdrs0, card_mons = CMons0,
                      reader_mons = RMons0}) ->
    IsNonExistent = is_reader_nonexistent(Evts),
    HasCard = is_card_present(Evts),
    {HadCard, WasNonExistent, OldATR} = case Rdrs0 of
        #{RdrName := #rdrstate{last_state = OldEvts, last_atr = A}} ->
            {is_card_present(OldEvts), is_reader_nonexistent(OldEvts), A};
        _ ->
            {false, true, <<>>}
    end,
    CheckATR = case {HadCard, HasCard} of
        {true, false} -> OldATR;
        _ -> ATR
    end,
    lists:foreach(fun ({ClientRef, {Pid, Filter}}) ->
        Matches = reader_matches_filter(RdrName, Filter),
        case {Matches, WasNonExistent, IsNonExistent} of
            {true, true, false} ->
                Pid ! {pcsc_reader, available, ClientRef, RdrName};
            {true, false, true} ->
                Pid ! {pcsc_reader, unavailable, ClientRef, RdrName};
            _ -> ok
        end
    end, maps:to_list(RMons0)),
    lists:foreach(fun ({ClientRef, {Pid, Filter}}) ->
        Matches = card_matches_filter(RdrName, CheckATR, Filter),
        case {Matches, HadCard, HasCard} of
            {true, false, true} ->
                Pid ! {pcsc_card, inserted, ClientRef, RdrName, ATR};
            {true, true, false} ->
                Pid ! {pcsc_card, removed, ClientRef, RdrName};
            _ -> ok
        end
    end, maps:to_list(CMons0)),
    Rdrs1 = Rdrs0#{
        RdrName => #rdrstate{last_state = Evts, last_atr = ATR}
    },
    {noreply, S0#?MODULE{readers = Rdrs1}};

handle_info(Msg = {pcsc_reader_error, MsgRef, Why},
                                            S0 = #?MODULE{msgref = MsgRef}) ->
    timer:sleep(50),
    case pcsc_nif:new_context() of
        {ok, Ctx1, MsgRef1} ->
            lager:warning("got pcsc_reader_error: ~p; restarted ok", [Why]),
            S1 = S0#?MODULE{ctx = Ctx1, msgref = MsgRef1},
            {noreply, S1};
        {error, {pcsc_error, _, no_readers, _}} ->
            lager:debug("no readers, sleeping for 1sec"),
            #?MODULE{readers = Rdrs0, card_mons = CMons0,
                     reader_mons = RMons0} = S0,
            Rdrs1 = maps:map(fun (RdrName, RdrState) ->
                #rdrstate{last_state = Evts, last_atr = ATR} = RdrState,
                HadCard = is_card_present(Evts),
                WasNonExistent = is_reader_nonexistent(Evts),
                lists:foreach(fun ({ClientRef, {Pid, Filter}}) ->
                    Matches = card_matches_filter(RdrName, ATR, Filter),
                    case {Matches, HadCard} of
                        {true, true} ->
                            Pid ! {pcsc_card, removed, ClientRef, RdrName};
                        _ -> ok
                    end
                end, maps:to_list(CMons0)),
                lists:foreach(fun ({ClientRef, {Pid, Filter}}) ->
                    Matches = reader_matches_filter(RdrName, Filter),
                    case {Matches, WasNonExistent} of
                        {true, false} ->
                            Pid ! {pcsc_reader, unavailable, ClientRef, RdrName};
                        _ -> ok
                    end
                end, maps:to_list(RMons0)),
                #rdrstate{last_state = [unknown], last_atr = <<>>}
            end, Rdrs0),
            timer:send_after(1000, Msg),
            {noreply, S0#?MODULE{readers = Rdrs1}};
        Err ->
            lager:warning("got pcsc_reader_error: ~p; retried and got ~p; "
                "sleeping for 5 sec", [Why, Err]),
            timer:send_after(5000, Msg),
            {noreply, S0}
    end.

%% @private
handle_cast(Msg, S0 = #?MODULE{}) ->
    {stop, {bad_cast, Msg}, S0}.

-spec reader_matches_filter(pcsc:rdrname(), reader_filter()) -> true | false.
reader_matches_filter(RdrName, F0 = #{name := ExactName}) ->
    F1 = maps:remove(name, F0),
    case RdrName of
        ExactName -> reader_matches_filter(RdrName, F1);
        _ -> false
    end;
reader_matches_filter(RdrName, F0 = #{name_prefix := Prefix}) ->
    F1 = maps:remove(name_prefix, F0),
    case binary:match(RdrName, [Prefix]) of
        {0, _} -> reader_matches_filter(RdrName, F1);
        _ -> false
    end;
reader_matches_filter(RdrName, F0 = #{name_contains := Contains}) ->
    F1 = maps:remove(name_contains, F0),
    case binary:match(RdrName, [Contains]) of
        nomatch -> false;
        _ -> reader_matches_filter(RdrName, F1)
    end;
reader_matches_filter(_RdrName, #{}) -> true.

-spec card_matches_filter(pcsc:rdrname(), binary(), card_filter()) -> true | false.
card_matches_filter(RdrName, CardATR, F0 = #{in_reader := RdrFilter}) ->
    F1 = maps:remove(in_reader, F0),
    case reader_matches_filter(RdrName, RdrFilter) of
        true -> card_matches_filter(RdrName, CardATR, F1);
        false -> false
    end;
card_matches_filter(RdrName, CardATR, F0 = #{atr := Exact}) ->
    F1 = maps:remove(atr, F0),
    case CardATR of
        Exact -> card_matches_filter(RdrName, CardATR, F1);
        _ -> false
    end;
card_matches_filter(RdrName, CardATR, F0 = #{atr_prefix := Prefix}) ->
    F1 = maps:remove(atr_prefix, F0),
    case binary:match(CardATR, [Prefix]) of
        {0, _} -> card_matches_filter(RdrName, CardATR, F1);
        _ -> false
    end;
card_matches_filter(RdrName, CardATR, F0 = #{atr_contains := Contains}) ->
    F1 = maps:remove(atr_contains, F0),
    case binary:match(CardATR, [Contains]) of
        nomatch -> false;
        _ -> card_matches_filter(RdrName, CardATR, F1)
    end;
card_matches_filter(_RdrName, _CardATR, #{}) -> true.
