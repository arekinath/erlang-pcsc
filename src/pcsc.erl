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

-module(pcsc).

-compile([{parse_transform, lager_transform}]).

-export_type([rdrname/0, sharemode/0, protocol/0, disposition/0,
    rdrstate/0]).

-include("iso7816.hrl").

-type rdrname() :: binary().
%% The unique name given to a particular PCSC card reader on the system.

-type sharemode() :: shared | exclusive | direct.
%% The "share mode" for a card or reader connection, which determines whether
%% there can be other connections open to this same card at the same time (and
%% therefore transactions are required to "lock" the reader). The
%% <code>direct</code> sharemode can be used to send APDUs directly to the
%% reader itself.

-type protocol() :: t0 | t1 | raw | direct.
%% The ISO7816 protocol in use to communicate with a particular card. The
%% <code>direct</code> protocol, if given to <code>pcsc_card:command()</code>,
%% will trigger the use of <code>SCardControl</code> to send a reader-directed
%% command.

-type disposition() :: leave | reset | unpower | eject.
%% Action to take at the end of a transaction or connection.

-type rdrstate() :: unknown | unavailable | empty | present | exclusive |
    inuse | mute.
%% State flags which show the current status of a PCSC card reader.
