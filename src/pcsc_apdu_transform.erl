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

%% @doc Behaviour for APDU transforms, as well as utility functions used by
%%      pcsc_card for dealing with them.
-module(pcsc_apdu_transform).

-behaviour(gen_server).
-compile([{parse_transform, lager_transform}]).

-export_type([mod/0, format/0]).

-type cmd_raw() :: term().
%% The type of an outgoing command after this transform has been applied to it
%% (ready for the next transformation below this one in the direction of raw
%% bytes)

-type cmd_cooked() :: term().
%% The type of an outgoing command received by this transform module.

-type reply_raw() :: term().
%% The type of an incoming command received by this transform module from
%% the previous transformation below this one (closer to raw bytes).

-type reply_cooked() :: term().
%% The type of an incoming command after this transform module has been
%% applied.

-type state() :: term().
%% Internal state of the transform module.

-type mod() :: module().
%% The name of a module which implements this behaviour.

-type format() :: atom().
%% A name for a "format": a type of data processed by an APDU transform.

-callback formats() -> {Cooked :: format() | [format()], Raw :: format() | [format()]}.
%% Returns atoms identifying the type of data which this module can
%% accept and produce.

-callback init(pcsc:protocol()) -> {ok, state()} | {error, term()}.
%% Initialise the transformation, returning an initial state.

-callback begin_transaction(state()) -> {ok, state()} | {error, term()}.
%% Called at the beginning of a card transaction.

-callback command(cmd_cooked(), state()) ->
    {ok, [cmd_raw()], state()} | {ok, [reply_cooked()], [cmd_raw()], state()} |
    {ok, state()} | {error, term()}.
%% Transform a command into output commands or replies.

-callback reply(reply_raw(), state()) ->
    {ok, [reply_cooked()], state()} | {ok, [cmd_raw()], [reply_cooked()], state()} |
    {ok, state()} | {error, term()}.
%% Transform a reply into cooked replies or further commands.

-callback end_transaction(state()) -> {ok, state()} | {ok, pcsc:disposition(), state()} | {error, term()}.
%% Called at the end of a card transaction. Can return a disposition,
%% which will be considered alongside all other transformations' returned
%% dispositions (the strictest of them will be used).

-callback terminate(state()) -> ok.

-export([
    start_link/2,
    command/2,
    reply/2,
    begin_transaction/1,
    end_transaction/1
]).

-export([
    init/1, terminate/2,
    handle_call/3,
    handle_cast/2
]).

%% @private
-spec start_link(module(), pcsc:protocol()) -> {ok, pid()} | {error, term()}.
start_link(Mod, Proto) ->
    gen_server:start_link(?MODULE, [Mod, Proto], []).

%% @private
-spec command(pid(), cmd_cooked()) -> {ok, [reply_cooked()], [cmd_raw()]} | {error, term()}.
command(Pid, Cmd0) ->
    gen_server:call(Pid, {command, Cmd0}).

%% @private
-spec reply(pid(), reply_raw()) -> {ok, [cmd_raw()], [reply_cooked()]} | {error, term()}.
reply(Pid, Reply0) ->
    gen_server:call(Pid, {reply, Reply0}).

%% @private
-spec begin_transaction(pid()) -> ok | {error, term()}.
begin_transaction(Pid) ->
    gen_server:call(Pid, begin_transaction).

%% @private
-spec end_transaction(pid()) -> ok | {ok, pcsc:disposition()} | {error, term()}.
end_transaction(Pid) ->
    gen_server:call(Pid, end_transaction).

-record(?MODULE, {
    mod :: atom(),
    modstate :: term()
}).

%% @private
init([Mod, Proto]) ->
    case Mod:init(Proto) of
        {ok, ModState0} ->
            {ok, #?MODULE{mod = Mod, modstate = ModState0}};
        Err ->
            {stop, Err}
    end.

%% @private
terminate(_Why, #?MODULE{mod = Mod, modstate = ModState0}) ->
    ok = Mod:terminate(ModState0).

%% @private
handle_call({command, Cmd0}, From, S0 = #?MODULE{mod = Mod, modstate = MS0}) ->
    case Mod:command(Cmd0, MS0) of
        {ok, MS1} ->
            {reply, {ok, [], []}, S0#?MODULE{modstate = MS1}};
        {ok, Cmds1, MS1} ->
            {reply, {ok, [], Cmds1}, S0#?MODULE{modstate = MS1}};
        {ok, Replies1, Cmds1, MS1} ->
            {reply, {ok, Replies1, Cmds1}, S0#?MODULE{modstate = MS1}};
        Err ->
            gen_server:reply(From, Err),
            {stop, Err, S0}
    end;

handle_call({reply, Reply0}, From, S0 = #?MODULE{mod = Mod, modstate = MS0}) ->
    case Mod:reply(Reply0, MS0) of
        {ok, MS1} ->
            {reply, {ok, [], []}, S0#?MODULE{modstate = MS1}};
        {ok, Replies1, MS1} ->
            {reply, {ok, [], Replies1}, S0#?MODULE{modstate = MS1}};
        {ok, Cmds1, Replies1, MS1} ->
            {reply, {ok, Cmds1, Replies1}, S0#?MODULE{modstate = MS1}};
        Err ->
            gen_server:reply(From, Err),
            {stop, Err, S0}
    end;

handle_call(begin_transaction, From, S0 = #?MODULE{mod = Mod, modstate = MS0}) ->
    case Mod:begin_transaction(MS0) of
        {ok, MS1} ->
            {reply, ok, S0#?MODULE{modstate = MS1}};
        Err ->
            gen_server:reply(From, Err),
            {stop, Err, S0}
    end;

handle_call(end_transaction, From, S0 = #?MODULE{mod = Mod, modstate = MS0}) ->
    case Mod:end_transaction(MS0) of
        {ok, MS1} ->
            {reply, ok, S0#?MODULE{modstate = MS1}};
        {ok, Dispos, MS1} ->
            {reply, {ok, Dispos}, S0#?MODULE{modstate = MS1}};
        Err ->
            gen_server:reply(From, Err),
            {stop, Err, S0}
    end.

%% @private
handle_cast(Msg, S0 = #?MODULE{}) ->
    {stop, {bad_cast, Msg}, S0}.
