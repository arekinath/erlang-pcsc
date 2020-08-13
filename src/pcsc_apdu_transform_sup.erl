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
-module(pcsc_apdu_transform_sup).

-behaviour(supervisor).
-compile([{parse_transform, lager_transform}]).

-export([
    start_link/2,
    verify/1,
    child_map/1
]).

-export([
    init/1
]).

-spec verify([atom()]) -> ok | {error, term()}.
verify(ModStack) ->
    verify(lists:reverse(ModStack), sets:from_list([binary])).
verify([], _PrevFormatSet) -> ok;
verify([NextMod | Rest], PrevFormatSet) ->
    case NextMod:formats() of
        {NextFormats, ModPrevFormats} ->
            NextFormatSet = sets:from_list(if
                is_list(NextFormats) -> NextFormats;
                true -> [NextFormats]
            end),
            ModPrevFormatSet = sets:from_list(if
                is_list(ModPrevFormats) -> ModPrevFormats;
                true -> [ModPrevFormats]
            end),
            case sets:is_disjoint(PrevFormatSet, ModPrevFormatSet) of
                true ->
                    {error, {no_accepted_format, NextMod, ModPrevFormats,
                        sets:to_list(PrevFormatSet)}};
                false ->
                    verify(Rest, NextFormatSet)
            end;
        _ ->
            {error, {bad_formats_return, NextMod}}
    end.

-spec start_link([atom()], pcsc:protocol()) -> {ok, pid()} | {error, term()}.
start_link(ModStack, Protocol) ->
    ok = verify(ModStack),
    supervisor:start_link(?MODULE, [ModStack, Protocol]).

-spec child_map(pid()) -> #{atom() => pid()}.
child_map(SupRef) ->
    List = supervisor:which_children(SupRef),
    lists:foldl(fun ({Mod, Pid, _, _}, Acc) ->
        Acc#{Mod => Pid}
    end, #{}, List).

init([ModStack, Protocol]) ->
    Flags = #{
        strategy => one_for_one,
        intensity => 5,
        period => 1
    },
    KidSpecs = [#{
        id => Mod,
        start => {pcsc_apdu_transform, start_link, [Mod, Protocol]},
        modules => [pcsc_apdu_transform, Mod]
    } || Mod <- ModStack],
    {ok, {Flags, KidSpecs}}.
