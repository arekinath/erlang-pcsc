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

%% @doc A pcsc_apdu_transform implementation which handles ISO7816 command
%%      and response chaining.
%%
%% With this transformation enabled, you can send long APDUs using a single
%% <code>iso7816:apdu_cmd()</code> record containing all of the concatenated
%% data. The transformation will handle breaking it up into a series of
%% chained smaller APDUs.
%%
%% When a card replies with the <code>61XX</code> "continue" response code,
%% this transformation will also take over and issue <code>GET_RESPONSE</code>
%% commands as needed until the full length has been read, giving you a single
%% <code>iso7816:apdu_reply()</code> record containing all of the data and the
%% final status word.
-module(iso7816_chain).

-include("iso7816.hrl").

-behaviour(pcsc_apdu_transform).

-export([
    formats/0,
    init/1,
    begin_transaction/1,
    command/2,
    reply/2,
    end_transaction/1,
    terminate/1
]).

-record(?MODULE, {
    % the source xAPDU for any in-progress command chaining
    source :: undefined | iso7816:apdu_cmd(),
    % the offset in the source xAPDU's data that we're sending from next
    offset = 0 :: integer(),
    % spooled up data (reverse order) for response chaining
    spool = [] :: [binary()],
    % the last command we send (used for t0 workaround)
    last :: undefined | iso7816:apdu_cmd()
}).

% Max amount to send in one APDU (command chaining)
-define(CHAIN_PART_LEN, 16#FF).

%% @private
formats() -> {xapdu, apdu}.

%% @private
init(_Proto) ->
    {ok, #?MODULE{}}.

%% @private
begin_transaction(S = #?MODULE{}) ->
    {ok, S}.

%% @private
end_transaction(S = #?MODULE{}) ->
    {ok, S}.

%% @private
% Process a fresh incoming xapdu command.
command(A0 = #apdu_cmd{data = none}, S0 = #?MODULE{source = undefined}) ->
    S1 = S0#?MODULE{last = A0, source = undefined, spool = []},
    {ok, [A0], S1};
command(A0 = #apdu_cmd{data = D0}, S0 = #?MODULE{source = undefined}) ->
    if
        (byte_size(D0) > ?CHAIN_PART_LEN) ->
            % We'll have to split this xapdu into multiple APDUs.
            % Make the first one now and send it, we'll do the others after
            % we get a reply.
            D1 = binary:part(D0, {0, ?CHAIN_PART_LEN}),
            A1 = A0#apdu_cmd{cla = to_chain(A0#apdu_cmd.cla), data = D1},
            S1 = S0#?MODULE{source = A0, offset = ?CHAIN_PART_LEN,
                            spool = [], last = A1},
            {ok, [A1], S1};

        true ->
            % For ordinary commands which fit in a single APDU, just push
            % them on through
            S1 = S0#?MODULE{last = A0, source = undefined, spool = []},
            {ok, [A0], S1}
    end.

%% @private
% Last reply, or only reply (to a passed-through single APDU command)
reply(R0 = #apdu_reply{sw = ok, data = none},
                    S0 = #?MODULE{source = undefined, spool = Ds0}) ->
    D1 = case Ds0 of
        [] -> none;
        _ -> iolist_to_binary(lists:reverse(Ds0))
    end,
    R1 = R0#apdu_reply{data = D1},
    {ok, [R1], S0};
reply(R0 = #apdu_reply{sw = ok, data = D0},
                    S0 = #?MODULE{source = undefined, spool = Ds0}) ->
    Ds1 = [D0 | Ds0],
    R1 = R0#apdu_reply{data = iolist_to_binary(lists:reverse(Ds1))},
    {ok, [R1], S0};
reply(R0 = #apdu_reply{sw = {warning, _}, data = D0},
                    S0 = #?MODULE{source = undefined, spool = Ds0}) ->
    Ds1 = [D0 | Ds0],
    R1 = R0#apdu_reply{data = iolist_to_binary(lists:reverse(Ds1))},
    {ok, [R1], S0};

% First or subsequent reply (not last) in response chaining. Continue to
% spool up the data and ask for more with a GET_RESPONSE command.
reply(_R0 = #apdu_reply{sw = {continue, N}, data = D0},
                    S0 = #?MODULE{source = undefined, spool = Ds0})
                    when is_binary(D0) ->
    Ds1 = [D0 | Ds0],
    A0 = #apdu_cmd{ins = get_response, p1 = 0, p2 = 0, le = N},
    S1 = S0#?MODULE{spool = Ds1, last = A0},
    {ok, [A0], [], S1};

% T=0 devices can send this to let us know the Le for a non-retryable command
reply(_R0 = #apdu_reply{proto = t0, sw = {continue, N}, data = none},
                                    S0 = #?MODULE{source = undefined}) ->
    A0 = #apdu_cmd{ins = get_response, p1 = 0, p2 = 0, le = N},
    S1 = S0#?MODULE{last = A0},
    {ok, [A0], [], S1};

% T=0 devices send this to ask us to retry a command with the correct Le.
reply(_R0 = #apdu_reply{proto = t0, sw = {requires_le, Le}, data = none},
                                                S0 = #?MODULE{last = A0}) ->
    A1 = A0#apdu_cmd{le = Le, proto = t0},
    S1 = S0#?MODULE{last = A1},
    {ok, [A1], [], S1};

% Intermediate "ok" result during command chaining. The card is asking us to
% continue the chain.
reply(_R0 = #apdu_reply{sw = ok, data = none},
                            S0 = #?MODULE{source = A0, offset = Off0}) ->
    #apdu_cmd{cla = Cla0, data = D0} = A0,
    Rem = byte_size(D0) - Off0,
    Take = if (Rem > ?CHAIN_PART_LEN) -> ?CHAIN_PART_LEN; true -> Rem end,
    D1 = binary:part(D0, {Off0, Take}),
    if
        (Rem > ?CHAIN_PART_LEN) ->
            A1 = A0#apdu_cmd{cla = to_chain(Cla0), data = D1},
            S1 = S0#?MODULE{offset = Off0 + byte_size(D1), last = A1},
            {ok, [A1], [], S1};
        true ->
            % This is the last command chain APDU, so unset "source" -- the
            % next reply will be the final reply which should be handled above.
            A1 = A0#apdu_cmd{cla = Cla0, data = D1},
            S1 = S0#?MODULE{source = undefined, last = A1},
            {ok, [A1], [], S1}
    end;

% Any errors go through to the consumer.
reply(R = #apdu_reply{sw = _}, S0 = #?MODULE{}) ->
    {ok, [R], S0}.

%% @private
terminate(_S) ->
    ok.

to_chain(iso) -> {iso, chain};
to_chain({iso, Channel}) when is_integer(Channel) -> {iso, chain, Channel};
to_chain(I) when is_integer(I) -> I bor 16#80.
