/*
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
*/

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#if defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <wintypes.h>
#include <winscard.h>
#endif

#include "erl_nif.h"

static ErlNifResourceType *pcsc_nif_ctx_rsc;
static ErlNifResourceType *pcsc_nif_hdl_rsc;
static ErlNifThreadOpts *pcsc_nif_thread_opts;

static const char *SCARD_RDR_CHANGE_NAME = "\\\\?PnP?\\Notification";

enum pcsc_nif_io_type {
	PCSC_IO_CONNECT,
	PCSC_IO_RECONNECT,
	PCSC_IO_BEGIN_TXN,
	PCSC_IO_APDU,
	PCSC_IO_END_TXN,
	PCSC_IO_DISCONNECT,
	PCSC_IO_STOP
};

enum pcsc_nif_hdl_state {
	PCSC_HDL_INIT,
	PCSC_HDL_CONNECTED,
	PCSC_HDL_IN_TXN,
	PCSC_HDL_STOPPED
};

struct pcsc_nif_io {
	struct pcsc_nif_io *pni_next;
	enum pcsc_nif_io_type pni_type;
	uint8_t *pni_data;
	size_t pni_len;
};

struct pcsc_nif_hdl {
	struct pcsc_nif_ctx *pnh_ctx;

	ErlNifMutex *pnh_mtx;

	struct pcsc_nif_hdl *pnh_prev;
	struct pcsc_nif_hdl *pnh_next;

	enum pcsc_nif_hdl_state pnh_state;
	char *pnh_rdrname;
	DWORD pnh_share_mode;
	DWORD pnh_pref_proto;
	DWORD pnh_proto;
	DWORD pnh_dispos;
	SCARDHANDLE pnh_handle;

	ErlNifEnv *pnh_env;
	ERL_NIF_TERM pnh_ref;

	ErlNifPid pnh_owner;

	ErlNifTid pnh_io_tid;
	ErlNifCond *pnh_ioq_cond;
	struct pcsc_nif_io *pnh_ioq;
	struct pcsc_nif_io *pnh_ioq_tail;
};

struct pcsc_nif_ctx {
	SCARDCONTEXT pnc_context;
	ErlNifEnv *pnc_env;
	ERL_NIF_TERM pnc_ref;
	ErlNifMutex *pnc_mtx;
	ErlNifPid pnc_owner;
	ErlNifTid pnc_watch_tid;
	int pnc_stopping;
	struct pcsc_nif_hdl *pnc_handles;
};

static void
pcsc_nif_ctx_dtor(ErlNifEnv *env, void *obj)
{
	struct pcsc_nif_ctx *ctx = obj;
	enif_mutex_lock(ctx->pnc_mtx);
	ctx->pnc_stopping = 1;
	enif_mutex_unlock(ctx->pnc_mtx);
	SCardCancel(ctx->pnc_context);
	enif_thread_join(ctx->pnc_watch_tid, NULL);
	enif_mutex_destroy(ctx->pnc_mtx);
	enif_free_env(ctx->pnc_env);
	SCardReleaseContext(ctx->pnc_context);
}

static void
pcsc_nif_hdl_dtor(ErlNifEnv *env, void *obj)
{
	struct pcsc_nif_hdl *hdl = obj;
	struct pcsc_nif_ctx *ctx = hdl->pnh_ctx;

	enif_mutex_lock(ctx->pnc_mtx);
	enif_mutex_lock(hdl->pnh_mtx);
}

static ERL_NIF_TERM
pcsc_error_term(ErlNifEnv *env, int rv)
{
	ERL_NIF_TERM atomerr;
	switch (rv) {
	case SCARD_F_INTERNAL_ERROR:
		atomerr = enif_make_atom(env, "internal_error");
		break;
	case SCARD_E_CANCELLED:
		atomerr = enif_make_atom(env, "cancelled");
		break;
	case SCARD_E_INVALID_HANDLE:
		atomerr = enif_make_atom(env, "invalid_handle");
		break;
	case SCARD_E_INVALID_PARAMETER:
		atomerr = enif_make_atom(env, "invalid_parameter");
		break;
	case SCARD_E_UNKNOWN_READER:
		atomerr = enif_make_atom(env, "unknown_reader");
		break;
	case SCARD_E_TIMEOUT:
		atomerr = enif_make_atom(env, "timeout");
		break;
	case SCARD_E_SHARING_VIOLATION:
		atomerr = enif_make_atom(env, "sharing_violation");
		break;
	case SCARD_E_NO_SMARTCARD:
		atomerr = enif_make_atom(env, "no_smartcard");
		break;
	case SCARD_F_COMM_ERROR:
		atomerr = enif_make_atom(env, "comm_error");
		break;
	case SCARD_E_NOT_TRANSACTED:
		atomerr = enif_make_atom(env, "not_transacted");
		break;
	case SCARD_E_READER_UNAVAILABLE:
		atomerr = enif_make_atom(env, "reader_unavailable");
		break;
	case SCARD_E_NO_SERVICE:
		atomerr = enif_make_atom(env, "no_service");
		break;
	case SCARD_E_SERVICE_STOPPED:
		atomerr = enif_make_atom(env, "no_service");
		break;
	case SCARD_E_NO_READERS_AVAILABLE:
		atomerr = enif_make_atom(env, "no_readers");
		break;
	default:
		atomerr = enif_make_atom(env, "other");
	}
	return (enif_make_tuple2(env,
	    enif_make_atom(env, "error"),
	    enif_make_tuple4(env,
	        enif_make_atom(env, "pcsc_error"),
		enif_make_int(env, rv),
		atomerr,
		enif_make_string(env, pcsc_stringify_error(rv), ERL_NIF_LATIN1)
	    )
	));
}

static ERL_NIF_TERM
errno_error_term(ErlNifEnv *env, int eno)
{
	return (enif_make_tuple2(env,
	    enif_make_atom(env, "error"),
	    enif_make_tuple3(env,
	        enif_make_atom(env, "errno"),
		enif_make_int(env, eno),
		enif_make_string(env, strerror(eno), ERL_NIF_LATIN1)
	    )
	));
}

static ERL_NIF_TERM
event_state_to_list(ErlNifEnv *msgenv, DWORD dwEventState)
{
	ERL_NIF_TERM e = enif_make_list(msgenv, 0);
	if (dwEventState & SCARD_STATE_UNKNOWN) {
		e = enif_make_list_cell(msgenv,
		    enif_make_atom(msgenv, "unknown"), e);
	}
	if (dwEventState & SCARD_STATE_UNAVAILABLE) {
		e = enif_make_list_cell(msgenv,
		    enif_make_atom(msgenv, "unavailable"), e);
	}
	if (dwEventState & SCARD_STATE_EMPTY) {
		e = enif_make_list_cell(msgenv,
		    enif_make_atom(msgenv, "empty"), e);
	}
	if (dwEventState & SCARD_STATE_PRESENT) {
		e = enif_make_list_cell(msgenv,
		    enif_make_atom(msgenv, "present"), e);
	}
	if (dwEventState & SCARD_STATE_EXCLUSIVE) {
		e = enif_make_list_cell(msgenv,
		    enif_make_atom(msgenv, "exclusive"), e);
	}
	if (dwEventState & SCARD_STATE_INUSE) {
		e = enif_make_list_cell(msgenv,
		    enif_make_atom(msgenv, "inuse"), e);
	}
	if (dwEventState & SCARD_STATE_MUTE) {
		e = enif_make_list_cell(msgenv,
		    enif_make_atom(msgenv, "mute"), e);
	}
	return (e);
}

static void *
pcsc_nif_watch_thread(void *arg)
{
	struct pcsc_nif_ctx *ctx = arg;
	ErlNifEnv *msgenv;
	size_t stlen, stlen_max;
	size_t rdrslen;
	size_t i;
	SCARD_READERSTATE *st;
	char *rdrs, *rdr, *p;
	unsigned char *atrb;
	ERL_NIF_TERM atr, rdrbin, events;
	DWORD rv;
	ERL_NIF_TERM err, msg;
	ErlNifPid owner;
	int need_rdrs = 0;

	stlen_max = 16;
	stlen = 0;
	st = enif_alloc(stlen_max * sizeof (SCARD_READERSTATE));
	bzero(st, stlen_max * sizeof (SCARD_READERSTATE));

	while (1) {
		rv = SCardListReaders(ctx->pnc_context, NULL, NULL, &rdrslen);
		if (rv != 0) {
			msgenv = enif_alloc_env();
			err = pcsc_error_term(msgenv, rv);
			goto error;
		}
		rdrs = enif_alloc(rdrslen);
		rv = SCardListReaders(ctx->pnc_context, NULL, rdrs, &rdrslen);
		if (rv != 0) {
			msgenv = enif_alloc_env();
			err = pcsc_error_term(msgenv, rv);
			goto error;
		}

		p = rdrs;
		stlen = 0;
		while (*p != '\0') {
			if (st[stlen].szReader == SCARD_RDR_CHANGE_NAME)
				st[stlen].szReader = NULL;
			if (st[stlen].szReader == NULL ||
			    strcmp(st[stlen].szReader, p) != 0) {
				free(st[stlen].szReader);
				/* XXX: reader names might be utf-8 */
				st[stlen].szReader = strdup(p);
				st[stlen].dwCurrentState = SCARD_STATE_UNAWARE;
			}
			stlen++;
			if (stlen >= stlen_max) {
				stlen_max <<= 1;
				st = enif_realloc(st,
				    stlen_max * sizeof (SCARD_READERSTATE));
				for (i = stlen; i < stlen_max; ++i) {
					bzero(&st[i],
					    sizeof (SCARD_READERSTATE));
				}
			}
			/* XXX: reader names might be utf-8 */
			p += strlen(p) + 1;
		}
		for (i = stlen; i < stlen_max; ++i)
			bzero(&st[i], sizeof (SCARD_READERSTATE));
		enif_free(rdrs);

		st[stlen].szReader = SCARD_RDR_CHANGE_NAME;
		st[stlen].dwCurrentState = SCARD_STATE_UNAWARE;
		stlen++;

		need_rdrs = 0;
		while (!need_rdrs) {
			rv = SCardGetStatusChange(ctx->pnc_context, INFINITE,
			    st, stlen);
			if (rv == SCARD_E_UNKNOWN_READER) {
				need_rdrs = 1;
				break;
			} else if (rv != 0) {
				msgenv = enif_alloc_env();
				err = pcsc_error_term(msgenv, rv);
				goto error;
			}
			enif_mutex_lock(ctx->pnc_mtx);
			if (ctx->pnc_stopping) {
				enif_mutex_unlock(ctx->pnc_mtx);
				return (NULL);
			}
			owner = ctx->pnc_owner;

			for (i = 0; i < stlen; ++i) {
				if (!(st[i].dwEventState & SCARD_STATE_CHANGED))
					continue;

				if (st[i].szReader == SCARD_RDR_CHANGE_NAME) {
					need_rdrs = 1;
					continue;
				}

				msgenv = enif_alloc_env();
				events = event_state_to_list(msgenv,
				    st[i].dwEventState);
				atrb = enif_make_new_binary(msgenv,
				    st[i].cbAtr, &atr);
				rdrbin = enif_make_new_binary(msgenv,
				    st[i].szReader, strlen(st[i].szReader));
				bcopy(st[i].rgbAtr, atrb, st[i].cbAtr);
				msg = enif_make_tuple5(msgenv,
				    enif_make_atom(msgenv, "pcsc_reader"),
				    enif_make_copy(msgenv, ctx->pnc_ref),
				    rdrbin, events, atr);
				rv = enif_send(ctx->pnc_env, &owner, msgenv,
				    msg);
				enif_free_env(msgenv);

				st[i].dwCurrentState =
				    st[i].dwEventState & ~SCARD_STATE_CHANGED;
			}
			enif_mutex_unlock(ctx->pnc_mtx);
		}
	}

	return (NULL);

error:
	enif_mutex_lock(ctx->pnc_mtx);
	owner = ctx->pnc_owner;
	enif_mutex_unlock(ctx->pnc_mtx);

	msg = enif_make_tuple3(msgenv,
		enif_make_atom(msgenv, "pcsc_reader_error"),
		enif_make_copy(msgenv, ctx->pnc_ref),
		err);
	rv = enif_send(ctx->pnc_env, &owner, msgenv, msg);
	enif_free_env(msgenv);

	return (NULL);
}

static void *
pcsc_nif_io_thread(void *arg)
{
	struct pcsc_nif_hdl *hdl = arg;
	struct pcsc_nif_ctx *ctx = hdl->pnh_ctx;
	ErlNifEnv *msgenv;
	ERL_NIF_TERM ret, msg;
	DWORD rv;
	struct pcsc_nif_io *io;
	ErlNifPid owner;
	DWORD dispos;

	msgenv = enif_alloc_env();

	while (1) {
		enif_mutex_lock(hdl->pnh_mtx);
		while ((io = hdl->pnh_ioq) == NULL)
			enif_cond_wait(hdl->pnh_ioq_cond, hdl->pnh_mtx);
		hdl->pnh_ioq = io->pni_next;
		if (hdl->pnh_ioq == NULL)
			hdl->pnh_ioq_tail = NULL;
		dispos = hdl->pnh_dispos;
		enif_mutex_unlock(hdl->pnh_mtx);

		enif_clear_env(msgenv);

		switch (io->pni_type) {
		case PCSC_IO_CONNECT:
			if (hdl->pnh_state != PCSC_HDL_INIT) {
				ret = enif_make_tuple2(msgenv,
				    enif_make_atom(msgenv, "error"),
				    enif_make_atom(msgenv, "wrong_state"));
				break;
			}
			rv = SCardConnect(ctx->pnc_context, hdl->pnh_rdrname,
			    hdl->pnh_share_mode, hdl->pnh_pref_proto,
			    &hdl->pnh_handle, &hdl->pnh_proto);
			if (rv != SCARD_S_SUCCESS) {
				ret = pcsc_error_term(msgenv, rv);
				break;
			}
			ret = enif_make_atom(msgenv, "ok");
			hdl->pnh_state = PCSC_HDL_CONNECTED;
			break;
		case PCSC_IO_STOP:
			if (hdl->pnh_state == PCSC_HDL_CONNECTED) {
				SCardDisconnect(hdl->pnh_handle,
				    hdl->pnh_dispos);
			}
			return (NULL);
		}

		enif_mutex_lock(hdl->pnh_mtx);
		owner = hdl->pnh_owner;
		msg = enif_make_tuple3(msgenv,
		    enif_make_atom(msgenv, "pcsc_io"),
		    enif_make_copy(msgenv, hdl->pnh_ref),
		    ret);
		rv = enif_send(hdl->pnh_env, &owner, msgenv, msg);
		enif_mutex_unlock(hdl->pnh_mtx);
	}

	return (NULL);
}

static ERL_NIF_TERM
pcsc_nif_new_context(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct pcsc_nif_ctx *ctx;
	ERL_NIF_TERM ret;
	DWORD rv;

	ctx = enif_alloc_resource(pcsc_nif_ctx_rsc,
	    sizeof (struct pcsc_nif_ctx));
	bzero(ctx, sizeof (struct pcsc_nif_ctx));
	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
	    &ctx->pnc_context);
	if (rv != SCARD_S_SUCCESS) {
		enif_release_resource(ctx);
		return (pcsc_error_term(env, rv));
	}

	ctx->pnc_env = enif_alloc_env();
	ctx->pnc_mtx = enif_mutex_create("pcsc_ctx_mtx");
	enif_self(env, &ctx->pnc_owner);
	ctx->pnc_stopping = 0;
	ctx->pnc_handles = NULL;
	ctx->pnc_ref = enif_make_ref(ctx->pnc_env);

	rv = enif_thread_create("pcsc_ctx_watch_thread", &ctx->pnc_watch_tid,
	    pcsc_nif_watch_thread, ctx, pcsc_nif_thread_opts);
	if (rv != 0) {
		enif_mutex_destroy(ctx->pnc_mtx);
		enif_free_env(ctx->pnc_env);
		enif_release_resource(ctx);
		return (errno_error_term(env, rv));
	}

	ret = enif_make_resource(env, ctx);
	enif_release_resource(ctx);
	ret = enif_make_tuple3(env,
	    enif_make_atom(env, "ok"),
	    ret,
	    enif_make_copy(env, ctx->pnc_ref));
	return (ret);
}

static ERL_NIF_TERM
pcsc_nif_connect(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct pcsc_nif_ctx *ctx;
	struct pcsc_nif_hdl *hdl;
	struct pcsc_nif_io *io;
	ERL_NIF_TERM ret;
	DWORD rv;
	DWORD sharemode, proto;
	char sharemode_str[16];
	char proto_str[16];
	ErlNifBinary rdrbin;
	char rdr_str[256];

	if (argc != 4)
		return (enif_make_badarg(env));

	if (!enif_is_ref(argv[0]))
		return (enif_make_badarg(env));

	if (!enif_get_resource(env, argv[0], pcsc_nif_ctx_rsc, &ctx))
		return (enif_make_badarg(env));

	if (!enif_is_binary(env, argv[1]))
		return (enif_make_badarg(env));

	if (!enif_inspect_binary(env, argv[1], &rdrbin))
		return (enif_make_badarg(env));
	bcopy(rdrbin.data, rdr_str, rdrbin.size);
	rdr_str[rdrbin.size] = '\0';

	if (!enif_is_atom(argv[2]))
		return (enif_make_badarg(env));
	if (!enif_is_atom(argv[3]))
		return (enif_make_badarg(env));

	if (enif_get_atom(env, argv[2], sharemode_str, sizeof (sharemode_str),
	    ERL_NIF_LATIN1) <= sizeof (sharemode_str)) {
		if (strcmp(sharemode_str, "shared") == 0)
			sharemode = SCARD_SHARE_SHARED;
		else if (strcmp(sharemode_str, "exclusive") == 0)
			sharemode = SCARD_SHARE_EXCLUSIVE;
		else if (strcmp(sharemode_str, "direct") == 0)
			sharemode = SCARD_SHARE_DIRECT;
		else
			return (enif_make_badarg(env));
	} else {
		return (enif_make_badarg(env));
	}

	if (enif_get_atom(env, argv[3], proto_str, sizeof (proto_str),
	    ERL_NIF_LATIN1) <= sizeof (proto_str)) {
		if (strcmp(proto_str, "t0") == 0)
			proto = SCARD_PROTOCOL_T0;
		else if (strcmp(proto_str, "t1") == 0)
			proto = SCARD_PROTOCOL_T1;
		else if (strcmp(proto_str, "raw") == 0)
			proto = SCARD_PROTOCOL_RAW;
		else
			return (enif_make_badarg(env));
	} else {
		return (enif_make_badarg(env));
	}

	hdl = enif_alloc_resource(pcsc_nif_hdl_rsc,
	    sizeof (struct pcsc_nif_hdl));
	bzero(hdl, sizeof (struct pcsc_nif_hdl));

	hdl->pnh_ctx = ctx;
	hdl->pnh_env = enif_alloc_env();
	hdl->pnh_mtx = enif_mtx_create("pcsc_hdl_mtx");
	hdl->pnh_ioq_cond = enif_cond_create("pcsc_hdl_cond");

	enif_mutex_lock(ctx->pnc_mtx);
	enif_mutex_lock(hdl->pnh_mtx);

	rv = enif_thread_create("pcsc_hdl_io_thread", &ctx->pnh_io_tid,
	    pcsc_nif_io_thread, hdl, pcsc_nif_thread_opts);
	if (rv != 0) {
		enif_mutex_unlock(hdl->pnh_mtx);
		enif_mutex_unlock(ctx->pnc_mtx);

		enif_mutex_destroy(hdl->pnh_mtx);
		enif_cond_destroy(hdl->pnh_ioq_cond);
		enif_free_env(hdl->pnh_env);
		enif_release_resource(hdl);
		return (errno_error_term(env, rv));
	}

	/* XXX: reader names might be utf-8 */
	hdl->pnh_rdrname = strdup(rdr_str);
	hdl->pnh_share_mode = sharemode;
	hdl->pnh_pref_proto = proto;

	enif_self(env, &hdl->pnh_owner);
	hdl->pnh_state = PCSC_HDL_RUNNING;
	hdl->pnh_ref = enif_make_ref(hdl->pnh_env);

	io = enif_alloc(sizeof (struct pcsc_nif_io));
	bzero(io, sizeof (struct pcsc_nif_io));
	io->pni_type = PCSC_IO_CONNECT;

	hdl->pnh_ioq = io;
	hdl->pnh_ioq_tail = io;

	hdl->pnh_prev = NULL;
	hdl->pnh_next = ctx->pnc_handles;
	ctx->pnc_handles = hdl;

	enif_mutex_unlock(hdl->pnh_mtx);
	enif_mutex_unlock(ctx->pnc_mtx);

	ret = enif_make_resource(env, hdl);
	enif_release_resource(hdl);
	ret = enif_make_tuple3(env,
	    enif_make_atom(env, "ok"),
	    ret,
	    enif_make_copy(env, hdl->pnh_ref));
	return (ret);
}

static ERL_NIF_TERM
pcsc_nif_set_dispos(ElfNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct pcsc_nif_hdl *hdl;
	char dispos_str[16];
	DWORD dispos;

	if (argc != 2)
		return (enif_make_badarg(env));

	if (!enif_is_ref(argv[0]))
		return (enif_make_badarg(env));

	if (!enif_get_resource(env, argv[0], pcsc_nif_hdl_rsc, &hdl))
		return (enif_make_badarg(env));

	if (enif_get_atom(env, argv[1], dispos_str, sizeof (dispos_str),
	    ERL_NIF_LATIN1) <= sizeof (dispos_str)) {
		if (strcmp(dispos_str, "leave") == 0)
			dispos = SCARD_LEAVE_CARD;
		else if (strcmp(dispos_str, "reset") == 0)
			dispos = SCARD_RESET_CARD;
		else if (strcmp(dispos_str, "unpower") == 0)
			dispos = SCARD_UNPOWER_CARD;
		else if (strcmp(dispos_str, "eject") == 0)
			dispos = SCARD_EJECT_CARD;
		else
			return (enif_make_badarg(env));
	} else {
		return (enif_make_badarg(env));
	}

	enif_mutex_lock(hdl->pnh_mtx);
	hdl->pnh_dispos = dispos;
	enif_mutex_unlock(hdl->pnh_mtx);

	return (enif_make_atom(env, "ok"));
}

static int
pcsc_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM info)
{
	pcsc_nif_ctx_rsc = enif_open_resource_type(env, NULL, "pcsc_nif_ctx",
	    pcsc_nif_ctx_dtor, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
	    NULL);
	pcsc_nif_hdl_rsc = enif_open_resource_type(env, NULL, "pcsc_nif_hdl",
	    pcsc_nif_hdl_dtor, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
	    NULL);
	pcsc_nif_thread_opts = enif_thread_opts_create("pcsc_nif_thread_opts");
	return (0);
}

static void
pcsc_nif_unload(ErlNifEnv *env, void *priv_data)
{
	enif_thread_opts_destroy(pcsc_nif_thread_opts);
	pcsc_nif_thread_opts = NULL;
}

static ErlNifFunc nif_funcs[] = {
	{ "new_context", 0, pcsc_nif_new_context },
	{ "connect", 4, pcsc_nif_connect },
	{ "set_disposition", 2, pcsc_nif_set_dispos }
};

ERL_NIF_INIT(pcsc_nif, nif_funcs, pcsc_nif_load, NULL, NULL, pcsc_nif_unload);
