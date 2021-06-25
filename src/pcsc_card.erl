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

%% @doc A connection to a particular card or card reader, over which APDUs
%%      may be exchanged.
%%
%% <h3>Example</h3>
%% <pre>
%%  {ok, Readers} = pcsc_card_db:list_readers(),
%%  [Reader | _] = Readers,
%%  {ok, Card} = pcsc_card:start(Reader, shared, [t1, t0]),
%%  ok = pcsc_card:begin_transaction(Card),
%%  {ok, Replies} = pcsc_card:command(Card,
%%      #apdu_cmd{cla = iso, ins = select, data = &lt;&lt;...&gt;&gt;}),
%%  ok = pcsc_card:end_transaction(Card).
%% </pre>
-module(pcsc_card).

-behaviour(gen_server).

-compile([{parse_transform, lager_transform}]).

-export([
    start_link/3,
    start_link/4,
    start/3,
    start/4,
    set_transforms/2,
    disconnect/1,
    begin_transaction/1,
    end_transaction/1,
    end_transaction/2,
    command/2,
    command/3
]).

-export([
    init/1, terminate/2,
    handle_call/3, handle_info/2, handle_cast/2
]).

-type mod_or_fmt() :: pcsc_apdu_transform:mod() | pcsc_apdu_transform:format().

-type options() :: #{
    transforms => [pcsc_apdu_transform:mod()]
}. %%
%% Additional options for <code>start_link/4</code>.
%% <ul>
%%  <li><code>transforms</code>: initial set of transformation modules
%%      to be used (see <code>set_transforms/2</code>)</li>
%% </ul>

-export_types([options/0]).

%% @doc Starts a connection to a PCSC card in the given reader, supervised by
%% the current process. See also <code>start/3</code>.
-spec start_link(pcsc:rdrname(), pcsc:sharemode(), [pcsc:protocol()]) -> {ok, pid()} | {error, term()}.
start_link(RdrName, ShareMode, PrefProtos) ->
    gen_server:start_link(?MODULE, [RdrName, ShareMode, PrefProtos], []).

%% @doc Starts a connection to a PCSC card in the given reader, supervised by
%% the current process, with additional options. See also <code>start/3</code>.
-spec start_link(pcsc:rdrname(), pcsc:sharemode(), [pcsc:protocol()], options()) -> {ok, pid()} | {error, term()}.
start_link(RdrName, ShareMode, PrefProtos, Opts) ->
    gen_server:start_link(?MODULE, [RdrName, ShareMode, PrefProtos, Opts], []).

%% @doc Starts a connection to a PCSC card in the given reader. Once this returns
%% ok, the connection is ready to use. If <code>ShareMode</code> is set to
%% <code>shared</code>, however, then a transaction will need to be begun before
%% APDUs can be send with <code>command/2-3</code>
-spec start(pcsc:rdrname(), pcsc:sharemode(), [pcsc:protocol()]) -> {ok, pid()} | {error, term()}.
start(RdrName, ShareMode, PrefProtos) ->
    gen_server:start(?MODULE, [RdrName, ShareMode, PrefProtos], []).

%% @doc Starts a connection to a PCSC card in the given reader, with additional
%% options. See also <code>start/3</code>.
-spec start(pcsc:rdrname(), pcsc:sharemode(), [pcsc:protocol()], options()) -> {ok, pid()} | {error, term()}.
start(RdrName, ShareMode, PrefProtos, Opts) ->
    gen_server:start(?MODULE, [RdrName, ShareMode, PrefProtos, Opts], []).

%% @doc Disconnects from the card and shuts down this <code>pcsc_card</code>
%% process.
-spec disconnect(pid()) -> ok | {error, term()}.
disconnect(Pid) ->
    gen_server:call(Pid, disconnect, infinity).

%% @doc Changes the set of transform modules in use for the connection. Takes a
%% list of transformation module names, ordered from "cooked" to "raw". The
%% final module on the list must produce type "binary", raw APDU data to be
%% sent on the wire.
-spec set_transforms(pid(), [pcsc_apdu_transform:mod()]) -> ok | {error, term()}.
set_transforms(Pid, ModStack) ->
    gen_server:call(Pid, {set_transforms, ModStack}, infinity).

%% @doc Begins a transaction, for cards open in <code>shared</code> mode.
%% Note that beginning a transaction will open a monitor on the calling process,
%% and if it dies then the transaction will be ended with <code>reset</code>
%% disposition.
-spec begin_transaction(pid()) -> ok | {error, term()}.
begin_transaction(Pid) ->
    gen_server:call(Pid, begin_transaction, infinity).

%% @doc Ends a transaction, for cards open in <code>shared</code> mode.
-spec end_transaction(pid()) -> ok | {error, term()}.
end_transaction(Pid) -> end_transaction(Pid, leave).

%% @doc Ends a transaction, for cards open in <code>shared</code> mode. The
%% additional <code>Disposition</code> argument can be used to indicate whether
%% to reset or power down the card after the end of this transaction.
-spec end_transaction(pid(), pcsc:disposition()) -> ok | {error, term()}.
end_transaction(Pid, Dispos) ->
    gen_server:call(Pid, {end_transaction, Dispos}, infinity).

%% @doc Sends a command, using the format of the last transformation module
%% enabled. By default, <code>iso7816</code> is the only transform enabled,
%% meaning this function should be given <code>iso7816:apdu_cmd()</code>
%% records, and will return <code>iso7816:apdu_reply()</code> records.
-spec command(pid(), term()) -> {ok, [term()]} | {error, term()}.
command(Pid, Cmd) ->
    gen_server:call(Pid, {command, Cmd}, 30000).

%% @doc Sends a command using a specific format or transformation module.
%% The type of the <code>Cmd</code> argument and the returned list items is
%% set by the transform in question.
-spec command(pid(), mod_or_fmt(), term()) -> {ok, [term()]} | {error, term()}.
command(Pid, ModOrFormat, Cmd) ->
    gen_server:call(Pid, {command, ModOrFormat, Cmd}, 30000).

-record(?MODULE, {
    rdrname :: binary(),
    hdl :: pcsc_nif:handle(),
    msgref :: pcsc_nif:msgref(),
    proto :: pcsc:protocol(),
    txnmon = none :: none | reference(),
    modstack :: [atom()],
    modsup :: pid()
}).

%% @private
init([RdrName, ShareMode, Protos]) ->
    init([RdrName, ShareMode, Protos, #{}]);
init([RdrName, ShareMode, Protos, Opts]) ->
    DefaultMods = maps:get(transforms, Opts, [iso7816]),
    process_flag(trap_exit, true),
    case pcsc_nif:connect(RdrName, ShareMode, Protos) of
        {ok, Hdl, MsgRef} ->
            receive
                {pcsc_io, MsgRef, {ok, Protocol}} ->
                    {ok, ModSup} = pcsc_apdu_transform_sup:start_link(
                        DefaultMods, Protocol),
                    {ok, #?MODULE{hdl = Hdl, msgref = MsgRef,
                                  modstack = DefaultMods, modsup = ModSup,
                                  rdrname = RdrName, proto = Protocol}};
                {pcsc_io, MsgRef, Err} ->
                    lager:warning("pcsc_card connect failed async: ~p", [Err]),
                    {stop, Err}
            end;
        Err ->
            lager:warning("pcsc_card connect failed: ~p", [Err]),
            {stop, Err}
    end.

%% @private
terminate(_Why, #?MODULE{}) -> ok.

stackbelow(Mod, []) -> error({mod_not_found, Mod});
stackbelow(Mod, [Mod | Rest]) -> Rest;
stackbelow(Mod, [_OtherMod | Rest]) -> stackbelow(Mod, Rest).

do_replies([], _Mod, S0 = #?MODULE{}) ->
    {ok, [], S0};
do_replies([Reply | Rest], Mod, S0 = #?MODULE{}) ->
    case do_reply(Reply, Mod, S0) of
        {ok, Replies0, S1} ->
            case do_replies(Rest, Mod, S1) of
                {ok, Replies1, S2} ->
                    Replies2 = Replies0 ++ Replies1,
                    {ok, Replies2, S2};
                Err -> Err
            end;
        Err -> Err
    end.

do_reply(Reply, Mod, S0 = #?MODULE{modsup = ModSup, modstack = Stack0}) ->
    ModMap = pcsc_apdu_transform_sup:child_map(ModSup),
    #{Mod := Pid} = ModMap,
    case pcsc_apdu_transform:reply(Pid, Reply) of
        {ok, NewCmds, Replies0} ->
            lager:debug("xform reply @~p: ~p => ~p", [Mod, Reply, Replies0]),
            CmdStack = stackbelow(Mod, Stack0),
            case do_cmds(NewCmds, CmdStack, S0) of
                {ok, DownReplies0, S1} ->
                    case do_replies(DownReplies0, Mod, S1) of
                        {ok, Replies1, S2} ->
                            Replies2 = Replies0 ++ Replies1,
                            {ok, Replies2, S2};
                        Err -> Err
                    end;
                Err -> Err
            end;
        Err -> Err
    end.

do_cmds([], _ModStack, S0 = #?MODULE{}) ->
    {ok, [], S0};
do_cmds([Cmd | Rest], ModStack, S0 = #?MODULE{}) ->
    case do_cmd(Cmd, ModStack, S0) of
        {ok, Replies0, S1} ->
            case do_cmds(Rest, ModStack, S1) of
                {ok, Replies1, S2} ->
                    Replies2 = Replies0 ++ Replies1,
                    {ok, Replies2, S2};
                Err -> Err
            end;
        Err -> Err
    end.

do_cmd(Cmd0, [], S0 = #?MODULE{hdl = Hdl, msgref = MsgRef}) ->
    {Proto, Bin} = Cmd0,
    lager:debug("sending command ~p", [Cmd0]),
    true = is_atom(Proto),
    true = is_binary(Bin),
    ok = pcsc_nif:transmit(Hdl, Proto, Bin),
    receive
        {pcsc_io, MsgRef, {apdu, RecvProto, RecvBin}} ->
            lager:debug("got reply ~p", [{RecvProto, RecvBin}]),
            {ok, [{RecvProto, RecvBin}], S0};
        {pcsc_io, MsgRef, Err = {error, _}} ->
            {error, Err}
    end;
do_cmd(Cmd0, [Mod | Stack], S0 = #?MODULE{modsup = ModSup}) ->
    ModMap = pcsc_apdu_transform_sup:child_map(ModSup),
    #{Mod := Pid} = ModMap,
    case pcsc_apdu_transform:command(Pid, Cmd0) of
        {ok, Replies0, NewCmds} ->
            lager:debug("xform cmd @~p: ~p => ~p", [Mod, Cmd0, NewCmds]),
            case do_cmds(NewCmds, Stack, S0) of
                {ok, DownReplies0, S1} ->
                    case do_replies(DownReplies0, Mod, S1) of
                        {ok, Replies1, S2} ->
                            Replies2 = Replies0 ++ Replies1,
                            {ok, Replies2, S2};
                        Err -> Err
                    end;
                Err -> Err
            end;
        Err -> Err
    end.

%% @private
handle_call({command, Cmd}, From, S0 = #?MODULE{modstack = Stack}) ->
    handle_call({command, lists:last(Stack), Cmd}, From, S0);

handle_call({command, Mod0, Cmd}, _From, S0 = #?MODULE{modstack = Stack0}) ->
    Mod = case lists:member(Mod0, Stack0) of
        true -> Mod0;
        false ->
            Formats = [{M, M:formats()} || M <- Stack0],
            Matches = [M || {M, {Cooked, _Raw}} <- Formats,
                lists:member(Mod0,
                    if is_list(Cooked) -> Cooked; true -> [Cooked] end)],
            case Matches of
                [] -> undefined;
                [M | _] -> M
            end
    end,
    case Mod of
        undefined ->
            {reply, {error, bad_format}, S0};
        _ ->
            CmdStack = [Mod | stackbelow(Mod, Stack0)],
            case do_cmd(Cmd, CmdStack, S0) of
                {ok, Replies, S1} ->
                    {reply, {ok, Replies}, S1};
                Err ->
                    {reply, Err, S0}
            end
    end;

handle_call(begin_transaction, _From = {Pid, _Tag},
        S0 = #?MODULE{txnmon = none, hdl = Hdl, msgref = MsgRef,
                      modsup = ModSup}) ->
    ok = pcsc_nif:begin_transaction(Hdl),
    receive
        {pcsc_io, MsgRef, ok} ->
            MRef = erlang:monitor(process, Pid),
            ModMap = pcsc_apdu_transform_sup:child_map(ModSup),
            lists:foreach(fun ({_Mod, ModPid}) ->
                ok = pcsc_apdu_transform:begin_transaction(ModPid)
            end, maps:to_list(ModMap)),
            S1 = S0#?MODULE{txnmon = MRef},
            {reply, ok, S1};
        {pcsc_io, MsgRef, Err = {error, _}} ->
            {reply, Err, S0}
    end;
handle_call(begin_transaction, _From, S0 = #?MODULE{}) ->
    {reply, {error, already_transacted}, S0};

handle_call({end_transaction, _MinDispos}, _From, S0 = #?MODULE{txnmon = none}) ->
    {reply, {error, not_transacted}, S0};
handle_call({end_transaction, MinDispos}, _From,
        S0 = #?MODULE{txnmon = MonRef, hdl = Hdl, msgref = MsgRef,
                      modsup = ModSup, modstack = ModStack}) ->
    erlang:demonitor(MonRef),
    ModMap = pcsc_apdu_transform_sup:child_map(ModSup),
    Dispos = max_dispos(lists:foldl(fun (Mod, Acc) ->
        #{Mod := ModPid} = ModMap,
        case pcsc_apdu_transform:end_transaction(ModPid) of
            ok -> Acc;
            {ok, D} -> [D | Acc]
        end
    end, [MinDispos], ModStack)),
    ok = pcsc_nif:set_disposition(Hdl, Dispos),
    ok = pcsc_nif:end_transaction(Hdl),
    receive
        {pcsc_io, MsgRef, ok} ->
            S1 = S0#?MODULE{txnmon = none},
            {reply, ok, S1};
        {pcsc_io, MsgRef, Err = {error, _}} ->
            {reply, Err, S0}
    end;

handle_call({set_transforms, ModStack}, _, S0 = #?MODULE{modsup = OldPid}) ->
    case pcsc_apdu_transform_sup:verify(ModStack) of
        ok ->
            exit(OldPid, shutdown),
            receive
                {'EXIT', OldPid, _} -> ok
            end,
            {ok, NewPid} = pcsc_apdu_transform_sup:start_link(ModStack,
                S0#?MODULE.proto),
            {reply, ok, S0#?MODULE{modstack = ModStack, modsup = NewPid}};
        Err ->
            {reply, Err, S0}
    end;

handle_call({disconnect, Dispos}, From, S0 = #?MODULE{hdl = Hdl, msgref = MRef}) ->
    ok = pcsc_nif:set_disposition(Hdl, Dispos),
    ok = pcsc_nif:disconnect(Hdl),
    receive
        {pcsc_io, MRef, ok} ->
            gen_server:reply(From, ok),
            {stop, normal, S0};
        {pcsc_io, MRef, {error, {pcsc_error, _, badarg, _}}} ->
            % pcsclite seems to return this often when a reader has gone away
            % TODO: read the pcsclite code to see why
            gen_server:reply(From, ok),
            {stop, normal, S0};
        {pcsc_io, MRef, {error, {pcsc_error, _, E, _}}} when
                (E =:= reader_unavailable) or (E =:= no_smartcard) ->
            % the handle was already disconnected because the card/rdr is gone
            gen_server:reply(From, ok),
            {stop, normal, S0};
        {pcsc_io, MRef, Err = {error, _}} ->
            % xxx: maybe some other errors also
            {reply, Err, S0}
    end;

handle_call(disconnect, From, S0 = #?MODULE{hdl = Hdl, msgref = MRef}) ->
    ok = pcsc_nif:disconnect(Hdl),
    receive
        {pcsc_io, MRef, ok} ->
            gen_server:reply(From, ok),
            {stop, normal, S0};
        {pcsc_io, MRef, {error, {pcsc_error, _, badarg, _}}} ->
            % this error means the dispos was invalid, set it to "reset" and
            % try again? maybe it didn't like the one we set?
            handle_call({disconnect, reset}, From, S0);
        {pcsc_io, MRef, {error, {pcsc_error, _, E, _}}} when
                (E =:= reader_unavailable) or (E =:= no_smartcard) ->
            % the handle was already disconnected because the card/rdr is gone
            gen_server:reply(From, ok),
            {stop, normal, S0};
        {pcsc_io, MRef, Err = {error, _}} ->
            {reply, Err, S0}
    end;

handle_call(Msg, _From, S0 = #?MODULE{}) ->
    {stop, {bad_msg, Msg}, S0}.

%% @private
handle_info({'DOWN', MRef, process, Pid, _Why},
                S0 = #?MODULE{txnmon = MRef, hdl = Hdl, msgref = MsgRef,
                              modsup = ModSup, modstack = ModStack}) ->
    ModMap = pcsc_apdu_transform_sup:child_map(ModSup),
    Dispos = max_dispos(lists:foldl(fun (Mod, Acc) ->
        #{Mod := ModPid} = ModMap,
        case pcsc_apdu_transform:end_transaction(ModPid) of
            ok -> Acc;
            {ok, D} -> [D | Acc]
        end
    end, [reset], ModStack)),
    ok = pcsc_nif:set_disposition(Hdl, Dispos),
    ok = pcsc_nif:end_transaction(Hdl),
    receive
        {pcsc_io, MsgRef, ok} ->
            S1 = S0#?MODULE{txnmon = none},
            {noreply, S1};
        {pcsc_io, MsgRef, Err = {error, _}} ->
            lager:warning("failed to close transaction held by dead process "
                "~p: ~p", [Pid, Err]),
            {noreply, S0}
    end;

handle_info(Msg, S0 = #?MODULE{}) ->
    {stop, {bad_msg, Msg}, S0}.

%% @private
handle_cast(Msg, S0 = #?MODULE{}) ->
    {stop, {bad_cast, Msg}, S0}.

max_dispos(A, []) -> A;
max_dispos(A, [A | Rest]) -> max_dispos(A, Rest);
max_dispos(reset, [leave | Rest]) -> max_dispos(reset, Rest);
max_dispos(unpower, [leave | Rest]) -> max_dispos(unpower, Rest);
max_dispos(unpower, [reset | Rest]) -> max_dispos(unpower, Rest);
max_dispos(eject, [leave | Rest]) -> max_dispos(eject, Rest);
max_dispos(eject, [reset | Rest]) -> max_dispos(eject, Rest);
max_dispos(eject, [unpower | Rest]) -> max_dispos(eject, Rest);
max_dispos(_A, [Any | Rest]) -> max_dispos(Any, Rest).

-spec max_dispos([pcsc:disposition()]) -> pcsc:disposition().
max_dispos([A | Rest]) -> max_dispos(A, Rest).
