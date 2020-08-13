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

%% @private
-module(pcsc_nif).

-on_load(init/0).

-export_type([context/0, msgref/0, handle/0, pcsc_ctx_msg/0, pcsc_io_msg/0]).

-type context() :: reference().
-type msgref() :: reference().
-type handle() :: reference().

-type pcsc_ctx_msg() ::
    {pcsc_reader, msgref(), pcsc:rdrname(), Events :: [pcsc:rdrstate()], ATR :: binary()} |
    {pcsc_reader_error, msgref(), term()}.

-type pcsc_io_msg() ::
    {pcsc_io, msgref(), {ok, pcsc:protocol()}} |
    {pcsc_io, msgref(), ok} |
    {pcsc_io, msgref(), {error, term()}} |
    {pcsc_io, msgref(), {apdu, pcsc:protocol(), binary()}}.

-export([new_context/0, connect/3, transmit/3, disconnect/1]).
-export([begin_transaction/1, end_transaction/1]).
-export([change_context_owner/2, change_handle_owner/2, set_disposition/2]).

try_paths([Last], BaseName) ->
    filename:join([Last, BaseName]);
try_paths([Path | Next], BaseName) ->
    case filelib:is_dir(Path) of
        true ->
            WCard = filename:join([Path, "{lib,}" ++ BaseName ++ ".*"]),
            case filelib:wildcard(WCard) of
                [] -> try_paths(Next, BaseName);
                _ -> filename:join([Path, BaseName])
            end;
        false -> try_paths(Next, BaseName)
    end.

init() ->
    Paths0 = [
        filename:join(["..", lib, pcsc, priv]),
        filename:join(["..", priv]),
        filename:join([priv])
    ],
    Paths1 = case code:priv_dir(pcsc) of
        {error, bad_name} -> Paths0;
        Dir -> [Dir | Paths0]
    end,
    SoName = try_paths(Paths1, "pcsc_nif"),
    erlang:load_nif(SoName, 0).

-spec new_context() -> {ok, context(), msgref()} | {error, term()}.
new_context() -> error(no_nif).

-spec change_context_owner(context(), pid()) -> ok | {error, not_owner}.
change_context_owner(_Ctx, _NewOwner) -> error(no_nif).

-spec connect(pcsc:rdrname(), pcsc:sharemode(), [pcsc:protocol()]) -> {ok, handle(), msgref()} | {error, term()}.
connect(_RdrName, _ShareMode, _Proto) -> error(no_nif).

-spec set_disposition(handle(), pcsc:disposition()) -> ok.
set_disposition(_Hdl, _Dispos) -> error(no_nif).

-spec change_handle_owner(handle(), pid()) -> ok | {error, not_owner}.
change_handle_owner(_Ctx, _NewOwner) -> error(no_nif).

-spec begin_transaction(handle()) -> ok | {error, term()}.
begin_transaction(_Hdl) -> error(no_nif).

-spec end_transaction(handle()) -> ok | {error, term()}.
end_transaction(_Hdl) -> error(no_nif).

-spec transmit(handle(), pcsc:protocol(), binary()) -> ok | {error, term()}.
transmit(_Hdl, _Proto, _Apdu) -> error(no_nif).

-spec disconnect(handle()) -> ok | {error, term()}.
disconnect(_Hdl) -> error(no_nif).
