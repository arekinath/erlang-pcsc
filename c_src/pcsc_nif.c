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
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

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
static const size_t SCARD_RECV_BUF = 258;

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
	const SCARD_IO_REQUEST *pni_ioreq;
	uint8_t *pni_data;
	size_t pni_len;
};

struct pcsc_nif_hdl {
	ErlNifMutex *pnh_mtx;

	enum pcsc_nif_hdl_state pnh_state;

	SCARDCONTEXT pnh_context;

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
};

static uint64_t
monotime(void)
{
	struct timeval tv;
	uint64_t msec;
	gettimeofday(&tv, NULL);
	msec = tv.tv_sec * 1000;
	msec += tv.tv_usec / 1000;
	return (msec);
}

static void
pcsc_nif_ctx_dtor(ErlNifEnv *env, void *obj)
{
	struct pcsc_nif_ctx *ctx = obj;

	if(ctx->pnc_mtx == NULL) return;

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
	struct pcsc_nif_io *io;

	io = enif_alloc(sizeof (struct pcsc_nif_io));
	bzero(io, sizeof (struct pcsc_nif_io));
	io->pni_type = PCSC_IO_STOP;

	enif_mutex_lock(hdl->pnh_mtx);
	if (hdl->pnh_ioq_tail == NULL) {
		hdl->pnh_ioq = io;
		hdl->pnh_ioq_tail = io;
	} else {
		hdl->pnh_ioq_tail->pni_next = io;
		hdl->pnh_ioq_tail = io;
	}
	enif_mutex_unlock(hdl->pnh_mtx);
	enif_cond_signal(hdl->pnh_ioq_cond);

	enif_thread_join(hdl->pnh_io_tid, NULL);

	enif_cond_destroy(hdl->pnh_ioq_cond);
	enif_mutex_destroy(hdl->pnh_mtx);
	free(hdl->pnh_rdrname);
	enif_free_env(hdl->pnh_env);
	SCardReleaseContext(hdl->pnh_context);
}

static ERL_NIF_TERM
pcsc_error_term(ErlNifEnv *env, DWORD rv)
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
	size_t cnt, max, sz, ocnt;
	size_t rdrslen;
	size_t i;
	SCARD_READERSTATE *tpl;
	SCARD_READERSTATE *st;
	char *rdrs, *p;
	unsigned char *atrb, *rdrb;
	ERL_NIF_TERM atr, rdr, events;
	DWORD rv;
	ERL_NIF_TERM err, msg;
	ErlNifPid owner;
	int need_rdrs = 0;
	uint8_t *matches;
	int use_pnp_notif = 1;
	DWORD timeout = 30000;
	uint64_t last_time = 0, now;

	max = 32;
	cnt = 0;
	sz = max * sizeof (SCARD_READERSTATE);

	st = enif_alloc(sz);
	tpl = enif_alloc(sz);
	matches = enif_alloc(max);
	bzero(st, sz);
	bzero(tpl, sz);

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

		last_time = monotime();
		bzero(matches, max);
		ocnt = cnt;

		p = rdrs;
		while (*p != '\0') {
			int found = 0;
			for (i = 0; i < cnt; ++i) {
				if (strcmp(tpl[i].szReader, p) == 0) {
					found = 1;
					matches[i] = 1;
					break;
				}
			}
			if (!found) {
				bzero(&tpl[cnt], sizeof (SCARD_READERSTATE));
				tpl[cnt].szReader = strdup(p);
				tpl[cnt].dwCurrentState = SCARD_STATE_UNAWARE;
				cnt++;
				if (cnt >= max) {
					max <<= 1;
					sz <<= 1;
					tpl = enif_realloc(tpl, sz);
					matches = enif_realloc(matches, max);
				}
			}
			/* XXX: reader names might be utf-8 */
			p += strlen(p) + 1;
		}
		for (i = 0; i < ocnt && i < cnt; ++i) {
			if (!matches[i]) {
				/* Notify erlang the reader has gone away */
				msgenv = enif_alloc_env();
				events = event_state_to_list(msgenv, SCARD_STATE_UNKNOWN);
				atrb = enif_make_new_binary(msgenv, 0, &atr);
				rdrb = enif_make_new_binary(msgenv,
				    strlen(tpl[i].szReader), &rdr);
				bcopy(tpl[i].szReader, rdrb, strlen(tpl[i].szReader));
				msg = enif_make_tuple5(msgenv,
				    enif_make_atom(msgenv, "pcsc_reader"),
				    enif_make_copy(msgenv, ctx->pnc_ref),
				    rdr, events, atr);
				rv = enif_send(ctx->pnc_env, &owner, msgenv, msg);
				enif_free_env(msgenv);

				/* Copy the last entry on the list over it. */
				cnt--;
				bcopy(&tpl[cnt], &tpl[i], sizeof (SCARD_READERSTATE));
				bzero(&tpl[cnt], sizeof (SCARD_READERSTATE));
			}
		}
		enif_free(rdrs);

		if (use_pnp_notif) {
			/*
			 * Add the extra "reader" which tells us if new readers show up.
			 * This might not be supported, so try it, and if it isn't, fall
			 * back to periodic polling.
			 */
			bzero(&tpl[cnt], sizeof (SCARD_READERSTATE));
			tpl[cnt].szReader = strdup(SCARD_RDR_CHANGE_NAME);
			tpl[cnt].dwCurrentState = SCARD_STATE_UNAWARE;
			cnt++;
		}

		enif_free(st);
		st = enif_alloc(sz);

		need_rdrs = 0;
		while (!need_rdrs) {
			bcopy(tpl, st, sz);
			rv = SCardGetStatusChange(ctx->pnc_context, timeout, st, cnt);
			if (rv == SCARD_E_UNKNOWN_READER) {
				need_rdrs = 1;
				break;
			} else if (rv == SCARD_E_INVALID_PARAMETER && use_pnp_notif) {
				cnt--;
				free((void *)tpl[cnt].szReader);
				use_pnp_notif = 0;
				timeout = 1000;
				continue;
			} else if (rv == SCARD_E_TIMEOUT) {
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

			for (i = 0; i < cnt; ++i) {
				if (!(st[i].dwEventState & SCARD_STATE_CHANGED))
					continue;

				if (strcmp(st[i].szReader, SCARD_RDR_CHANGE_NAME) == 0) {
					need_rdrs = 1;
					continue;
				}

				msgenv = enif_alloc_env();
				events = event_state_to_list(msgenv, st[i].dwEventState);
				atrb = enif_make_new_binary(msgenv, st[i].cbAtr, &atr);
				rdrb = enif_make_new_binary(msgenv,
				    strlen(st[i].szReader), &rdr);
				bcopy(st[i].rgbAtr, atrb, st[i].cbAtr);
				bcopy(st[i].szReader, rdrb, strlen(st[i].szReader));
				msg = enif_make_tuple5(msgenv,
				    enif_make_atom(msgenv, "pcsc_reader"),
				    enif_make_copy(msgenv, ctx->pnc_ref),
				    rdr, events, atr);
				rv = enif_send(ctx->pnc_env, &owner, msgenv, msg);
				enif_free_env(msgenv);

				tpl[i].dwCurrentState = st[i].dwEventState;
			}
			enif_mutex_unlock(ctx->pnc_mtx);

			if (timeout != INFINITE) {
				now = monotime();
				if (now - last_time > timeout)
					need_rdrs = 1;
			}
		}

		if (use_pnp_notif) {
			/* Take back the new reader notifier. */
			cnt--;
			free((void *)tpl[cnt].szReader);
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
	ErlNifEnv *msgenv;
	ERL_NIF_TERM ret, msg, binterm;
	DWORD rv;
	struct pcsc_nif_io *io;
	ErlNifPid owner;
	DWORD dispos;
	ErlNifBinary recvbin;
	DWORD recv_len;
	SCARD_IO_REQUEST ioreq;

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
		ret = enif_make_tuple2(msgenv,
		    enif_make_atom(msgenv, "error"),
		    enif_make_atom(msgenv, "not_implemented"));

		switch (io->pni_type) {
		case PCSC_IO_CONNECT:
			if (hdl->pnh_state != PCSC_HDL_INIT) {
				ret = enif_make_tuple2(msgenv,
				    enif_make_atom(msgenv, "error"),
				    enif_make_atom(msgenv, "bad_state"));
				break;
			}
			rv = SCardConnect(hdl->pnh_context, hdl->pnh_rdrname,
			    hdl->pnh_share_mode, hdl->pnh_pref_proto,
			    &hdl->pnh_handle, &hdl->pnh_proto);
			if (rv != SCARD_S_SUCCESS) {
				ret = pcsc_error_term(msgenv, rv);
				break;
			}
			switch (hdl->pnh_proto) {
			case SCARD_PROTOCOL_T0:
				ret = enif_make_atom(msgenv, "t0");
				break;
			case SCARD_PROTOCOL_T1:
				ret = enif_make_atom(msgenv, "t1");
				break;
			case SCARD_PROTOCOL_RAW:
				ret = enif_make_atom(msgenv, "raw");
				break;
			default:
				ret = enif_make_atom(msgenv, "direct");
				break;
			}
			ret = enif_make_tuple2(msgenv,
			    enif_make_atom(msgenv, "ok"),
			    ret);
			hdl->pnh_state = PCSC_HDL_CONNECTED;
			break;
		case PCSC_IO_DISCONNECT:
			if (hdl->pnh_state != PCSC_HDL_CONNECTED) {
				ret = enif_make_tuple2(msgenv,
				    enif_make_atom(msgenv, "error"),
				    enif_make_atom(msgenv, "bad_state"));
				break;
			}
			rv = SCardDisconnect(hdl->pnh_handle, dispos);
			if (rv != SCARD_S_SUCCESS) {
				ret = pcsc_error_term(msgenv, rv);
				break;
			}
			hdl->pnh_state = PCSC_HDL_INIT;
			ret = enif_make_atom(msgenv, "ok");
			break;
		case PCSC_IO_RECONNECT:
			if (hdl->pnh_state != PCSC_HDL_CONNECTED) {
				ret = enif_make_tuple2(msgenv,
				    enif_make_atom(msgenv, "error"),
				    enif_make_atom(msgenv, "bad_state"));
				break;
			}
			rv = SCardReconnect(hdl->pnh_handle, hdl->pnh_share_mode,
			    hdl->pnh_pref_proto, SCARD_RESET_CARD, &hdl->pnh_proto);
			if (rv != SCARD_S_SUCCESS) {
				ret = pcsc_error_term(msgenv, rv);
				break;
			}
			switch (hdl->pnh_proto) {
			case SCARD_PROTOCOL_T0:
				ret = enif_make_atom(msgenv, "t0");
				break;
			case SCARD_PROTOCOL_T1:
				ret = enif_make_atom(msgenv, "t1");
				break;
			case SCARD_PROTOCOL_RAW:
				ret = enif_make_atom(msgenv, "raw");
				break;
			default:
				ret = enif_make_atom(msgenv, "direct");
				break;
			}
			ret = enif_make_tuple2(msgenv,
			    enif_make_atom(msgenv, "ok"),
			    ret);
			break;
		case PCSC_IO_BEGIN_TXN:
			if (hdl->pnh_state != PCSC_HDL_CONNECTED) {
				ret = enif_make_tuple2(msgenv,
				    enif_make_atom(msgenv, "error"),
				    enif_make_atom(msgenv, "bad_state"));
				break;
			}
			rv = SCardBeginTransaction(hdl->pnh_handle);
			if (rv != SCARD_S_SUCCESS) {
				ret = pcsc_error_term(msgenv, rv);
				break;
			}
			ret = enif_make_atom(msgenv, "ok");
			hdl->pnh_state = PCSC_HDL_IN_TXN;
			break;
		case PCSC_IO_END_TXN:
			if (hdl->pnh_state != PCSC_HDL_IN_TXN) {
				ret = enif_make_tuple2(msgenv,
				    enif_make_atom(msgenv, "error"),
				    enif_make_atom(msgenv, "bad_state"));
				break;
			}
			rv = SCardEndTransaction(hdl->pnh_handle, dispos);
			if (rv != SCARD_S_SUCCESS) {
				ret = pcsc_error_term(msgenv, rv);
				break;
			}
			ret = enif_make_atom(msgenv, "ok");
			hdl->pnh_state = PCSC_HDL_CONNECTED;
			break;
		case PCSC_IO_APDU:
			if (hdl->pnh_state != PCSC_HDL_IN_TXN &&
			    hdl->pnh_state != PCSC_HDL_CONNECTED) {
				ret = enif_make_tuple2(msgenv,
				    enif_make_atom(msgenv, "error"),
				    enif_make_atom(msgenv, "bad_state"));
				break;
			}
			if (io->pni_ioreq != NULL) {
				bcopy(io->pni_ioreq, &ioreq, sizeof (ioreq));
			} else {
				bzero(&ioreq, sizeof (ioreq));
			}
			if (!enif_alloc_binary(SCARD_RECV_BUF, &recvbin)) {
				ret = enif_make_tuple2(msgenv,
				    enif_make_atom(msgenv, "error"),
				    enif_make_atom(msgenv, "alloc_fail"));
				break;
			}
			bzero(recvbin.data, SCARD_RECV_BUF);
			recv_len = SCARD_RECV_BUF;
			if (io->pni_ioreq != NULL) {
				rv = SCardTransmit(hdl->pnh_handle,
				    io->pni_ioreq, io->pni_data, io->pni_len,
				    &ioreq, recvbin.data, &recv_len);
			} else {
				/* Assume "direct" means a rdr escape command */
				rv = SCardControl(hdl->pnh_handle, 0x42000000 + 1,
				    io->pni_data, io->pni_len,
				    recvbin.data, recv_len, &recv_len);
			}
			if (rv != SCARD_S_SUCCESS) {
				enif_release_binary(&recvbin);
				ret = pcsc_error_term(msgenv, rv);
				break;
			}
			binterm = enif_make_binary(msgenv, &recvbin);
			binterm = enif_make_sub_binary(msgenv, binterm,
			    0, recv_len);
			switch (ioreq.dwProtocol) {
			case SCARD_PROTOCOL_T0:
				ret = enif_make_atom(msgenv, "t0");
				break;
			case SCARD_PROTOCOL_T1:
				ret = enif_make_atom(msgenv, "t1");
				break;
			case SCARD_PROTOCOL_RAW:
				ret = enif_make_atom(msgenv, "raw");
				break;
			default:
				ret = enif_make_atom(msgenv, "direct");
				break;
			}
			ret = enif_make_tuple3(msgenv,
			    enif_make_atom(msgenv, "apdu"),
			    ret, binterm);
			break;
		case PCSC_IO_STOP:
			if (hdl->pnh_state == PCSC_HDL_IN_TXN) {
				(void) SCardEndTransaction(hdl->pnh_handle, dispos);
				hdl->pnh_state = PCSC_HDL_CONNECTED;
			}
			if (hdl->pnh_state == PCSC_HDL_CONNECTED) {
				(void) SCardDisconnect(hdl->pnh_handle, dispos);
			}
			return (NULL);
		}

		enif_free(io->pni_data);
		enif_free(io);

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
	struct pcsc_nif_hdl *hdl;
	struct pcsc_nif_io *io;
	ERL_NIF_TERM ret, head, tail;
	DWORD rv;
	DWORD sharemode, proto;
	char sharemode_str[16];
	char proto_str[16];
	ErlNifBinary rdrbin;
	char rdr_str[256];

	if (argc != 3)
		return (enif_make_badarg(env));

	if (!enif_is_binary(env, argv[0]))
		return (enif_make_badarg(env));

	if (!enif_inspect_binary(env, argv[0], &rdrbin))
		return (enif_make_badarg(env));
	bcopy(rdrbin.data, rdr_str, rdrbin.size);
	rdr_str[rdrbin.size] = '\0';

	if (!enif_is_atom(env, argv[1]))
		return (enif_make_badarg(env));

	if (enif_get_atom(env, argv[1], sharemode_str, sizeof (sharemode_str),
	    ERL_NIF_LATIN1) < sizeof (sharemode_str)) {
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

	if (!enif_is_list(env, argv[2]))
		return (enif_make_badarg(env));
	tail = argv[2];
	proto = 0;
	while (enif_get_list_cell(env, tail, &head, &tail)) {
		if (!enif_is_atom(env, head))
			return (enif_make_badarg(env));
		rv = enif_get_atom(env, head, proto_str, sizeof (proto_str),
		    ERL_NIF_LATIN1);
		if (rv < sizeof (proto_str)) {
			if (strcmp(proto_str, "t0") == 0)
				proto |= SCARD_PROTOCOL_T0;
			else if (strcmp(proto_str, "t1") == 0)
				proto |= SCARD_PROTOCOL_T1;
			else if (strcmp(proto_str, "raw") == 0)
				proto |= SCARD_PROTOCOL_RAW;
			else if (strcmp(proto_str, "direct") == 0)
				proto |= SCARD_PROTOCOL_UNDEFINED;
			else
				return (enif_make_badarg(env));
		} else {
			return (enif_make_badarg(env));
		}
	}

	hdl = enif_alloc_resource(pcsc_nif_hdl_rsc,
	    sizeof (struct pcsc_nif_hdl));
	bzero(hdl, sizeof (struct pcsc_nif_hdl));

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
	    &hdl->pnh_context);
	if (rv != SCARD_S_SUCCESS) {
		enif_release_resource(hdl);
		return (pcsc_error_term(env, rv));
	}

	hdl->pnh_env = enif_alloc_env();
	hdl->pnh_mtx = enif_mutex_create("pcsc_hdl_mtx");
	hdl->pnh_ioq_cond = enif_cond_create("pcsc_hdl_cond");

	enif_mutex_lock(hdl->pnh_mtx);

	rv = enif_thread_create("pcsc_hdl_io_thread", &hdl->pnh_io_tid,
	    pcsc_nif_io_thread, hdl, pcsc_nif_thread_opts);
	if (rv != 0) {
		enif_mutex_unlock(hdl->pnh_mtx);
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
	hdl->pnh_state = PCSC_HDL_INIT;
	hdl->pnh_ref = enif_make_ref(hdl->pnh_env);

	io = enif_alloc(sizeof (struct pcsc_nif_io));
	bzero(io, sizeof (struct pcsc_nif_io));
	io->pni_type = PCSC_IO_CONNECT;

	hdl->pnh_ioq = io;
	hdl->pnh_ioq_tail = io;

	enif_mutex_unlock(hdl->pnh_mtx);

	ret = enif_make_resource(env, hdl);
	enif_release_resource(hdl);
	ret = enif_make_tuple3(env,
	    enif_make_atom(env, "ok"),
	    ret,
	    enif_make_copy(env, hdl->pnh_ref));
	return (ret);
}

static ERL_NIF_TERM
pcsc_nif_set_dispos(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct pcsc_nif_hdl *hdl;
	char dispos_str[16];
	DWORD dispos;

	if (argc != 2)
		return (enif_make_badarg(env));

	if (!enif_is_ref(env, argv[0]))
		return (enif_make_badarg(env));

	if (!enif_get_resource(env, argv[0], pcsc_nif_hdl_rsc, (void **)&hdl))
		return (enif_make_badarg(env));

	if (!enif_is_atom(env, argv[1]))
		return (enif_make_badarg(env));

	if (enif_get_atom(env, argv[1], dispos_str, sizeof (dispos_str),
	    ERL_NIF_LATIN1) < sizeof (dispos_str)) {
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

static ERL_NIF_TERM
pcsc_nif_change_hdl_owner(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct pcsc_nif_hdl *hdl;
	ErlNifPid self;
	ErlNifPid new_owner;
	ERL_NIF_TERM ret;

	if (argc != 2)
		return (enif_make_badarg(env));

	if (!enif_is_ref(env, argv[0]))
		return (enif_make_badarg(env));

	if (!enif_get_resource(env, argv[0], pcsc_nif_hdl_rsc, (void **)&hdl))
		return (enif_make_badarg(env));

	if (!enif_is_pid(env, argv[1]))
		return (enif_make_badarg(env));

	if (!enif_get_local_pid(env, argv[1], &new_owner))
		return (enif_make_badarg(env));
	enif_self(env, &self);

	enif_mutex_lock(hdl->pnh_mtx);
	if (enif_compare_pids(&hdl->pnh_owner, &self) == 0) {
		hdl->pnh_owner = new_owner;
		ret = enif_make_atom(env, "ok");
	} else {
		ret = enif_make_tuple2(env,
		    enif_make_atom(env, "error"),
		    enif_make_atom(env, "not_owner"));
	}
	enif_mutex_unlock(hdl->pnh_mtx);

	return (ret);
}

static ERL_NIF_TERM
pcsc_nif_change_ctx_owner(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct pcsc_nif_ctx *ctx;
	ErlNifPid self;
	ErlNifPid new_owner;
	ERL_NIF_TERM ret;

	if (argc != 2)
		return (enif_make_badarg(env));

	if (!enif_is_ref(env, argv[0]))
		return (enif_make_badarg(env));

	if (!enif_get_resource(env, argv[0], pcsc_nif_ctx_rsc, (void **)&ctx))
		return (enif_make_badarg(env));

	if (!enif_is_pid(env, argv[1]))
		return (enif_make_badarg(env));

	if (!enif_get_local_pid(env, argv[1], &new_owner))
		return (enif_make_badarg(env));
	enif_self(env, &self);

	enif_mutex_lock(ctx->pnc_mtx);
	if (enif_compare_pids(&ctx->pnc_owner, &self) == 0) {
		ctx->pnc_owner = new_owner;
		ret = enif_make_atom(env, "ok");
	} else {
		ret = enif_make_tuple2(env,
		    enif_make_atom(env, "error"),
		    enif_make_atom(env, "not_owner"));
	}
	enif_mutex_unlock(ctx->pnc_mtx);

	return (ret);
}

static ERL_NIF_TERM
pcsc_nif_disconnect(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct pcsc_nif_hdl *hdl;
	struct pcsc_nif_io *io;

	if (argc != 1)
		return (enif_make_badarg(env));

	if (!enif_is_ref(env, argv[0]))
		return (enif_make_badarg(env));

	if (!enif_get_resource(env, argv[0], pcsc_nif_hdl_rsc, (void **)&hdl))
		return (enif_make_badarg(env));

	io = enif_alloc(sizeof (struct pcsc_nif_io));
	bzero(io, sizeof (struct pcsc_nif_io));
	io->pni_type = PCSC_IO_DISCONNECT;

	enif_mutex_lock(hdl->pnh_mtx);
	if (hdl->pnh_state != PCSC_HDL_CONNECTED) {
		enif_mutex_unlock(hdl->pnh_mtx);
		enif_free(io);
		return (enif_make_tuple2(env,
		    enif_make_atom(env, "error"),
		    enif_make_atom(env, "bad_state")));
	}
	if (hdl->pnh_ioq_tail == NULL) {
		hdl->pnh_ioq = io;
		hdl->pnh_ioq_tail = io;
	} else {
		hdl->pnh_ioq_tail->pni_next = io;
		hdl->pnh_ioq_tail = io;
	}
	enif_mutex_unlock(hdl->pnh_mtx);
	enif_cond_signal(hdl->pnh_ioq_cond);

	return (enif_make_atom(env, "ok"));
}

static ERL_NIF_TERM
pcsc_nif_begin_txn(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct pcsc_nif_hdl *hdl;
	struct pcsc_nif_io *io;

	if (argc != 1)
		return (enif_make_badarg(env));

	if (!enif_is_ref(env, argv[0]))
		return (enif_make_badarg(env));

	if (!enif_get_resource(env, argv[0], pcsc_nif_hdl_rsc, (void **)&hdl))
		return (enif_make_badarg(env));

	io = enif_alloc(sizeof (struct pcsc_nif_io));
	bzero(io, sizeof (struct pcsc_nif_io));
	io->pni_type = PCSC_IO_BEGIN_TXN;

	enif_mutex_lock(hdl->pnh_mtx);
	if (hdl->pnh_state != PCSC_HDL_CONNECTED) {
		enif_mutex_unlock(hdl->pnh_mtx);
		enif_free(io);
		return (enif_make_tuple2(env,
		    enif_make_atom(env, "error"),
		    enif_make_atom(env, "bad_state")));
	}
	if (hdl->pnh_ioq_tail == NULL) {
		hdl->pnh_ioq = io;
		hdl->pnh_ioq_tail = io;
	} else {
		hdl->pnh_ioq_tail->pni_next = io;
		hdl->pnh_ioq_tail = io;
	}
	enif_mutex_unlock(hdl->pnh_mtx);
	enif_cond_signal(hdl->pnh_ioq_cond);

	return (enif_make_atom(env, "ok"));
}

static ERL_NIF_TERM
pcsc_nif_end_txn(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct pcsc_nif_hdl *hdl;
	struct pcsc_nif_io *io;

	if (argc != 1)
		return (enif_make_badarg(env));

	if (!enif_is_ref(env, argv[0]))
		return (enif_make_badarg(env));

	if (!enif_get_resource(env, argv[0], pcsc_nif_hdl_rsc, (void **)&hdl))
		return (enif_make_badarg(env));

	io = enif_alloc(sizeof (struct pcsc_nif_io));
	bzero(io, sizeof (struct pcsc_nif_io));
	io->pni_type = PCSC_IO_END_TXN;

	enif_mutex_lock(hdl->pnh_mtx);
	if (hdl->pnh_state != PCSC_HDL_IN_TXN) {
		enif_mutex_unlock(hdl->pnh_mtx);
		enif_free(io);
		return (enif_make_tuple2(env,
		    enif_make_atom(env, "error"),
		    enif_make_atom(env, "bad_state")));
	}
	if (hdl->pnh_ioq_tail == NULL) {
		hdl->pnh_ioq = io;
		hdl->pnh_ioq_tail = io;
	} else {
		hdl->pnh_ioq_tail->pni_next = io;
		hdl->pnh_ioq_tail = io;
	}
	enif_mutex_unlock(hdl->pnh_mtx);
	enif_cond_signal(hdl->pnh_ioq_cond);

	return (enif_make_atom(env, "ok"));
}

static ERL_NIF_TERM
pcsc_nif_transmit(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct pcsc_nif_hdl *hdl;
	struct pcsc_nif_io *io;
	char proto_str[16];
	ErlNifBinary bin;
	int rv;

	if (argc != 3)
		return (enif_make_badarg(env));

	if (!enif_is_ref(env, argv[0]))
		return (enif_make_badarg(env));

	if (!enif_get_resource(env, argv[0], pcsc_nif_hdl_rsc, (void **)&hdl))
		return (enif_make_badarg(env));

	if (!enif_is_atom(env, argv[1]))
		return (enif_make_badarg(env));

	if (!enif_is_binary(env, argv[2]))
		return (enif_make_badarg(env));

	io = enif_alloc(sizeof (struct pcsc_nif_io));
	bzero(io, sizeof (struct pcsc_nif_io));
	io->pni_type = PCSC_IO_APDU;

	rv = enif_get_atom(env, argv[1], proto_str, sizeof (proto_str),
	    ERL_NIF_LATIN1);
	if (rv < sizeof (proto_str)) {
		if (strcmp(proto_str, "t0") == 0) {
			io->pni_ioreq = SCARD_PCI_T0;
		} else if (strcmp(proto_str, "t1") == 0) {
			io->pni_ioreq = SCARD_PCI_T1;
		} else if (strcmp(proto_str, "raw") == 0) {
			io->pni_ioreq = SCARD_PCI_RAW;
		} else if (strcmp(proto_str, "direct") == 0) {
			io->pni_ioreq = NULL;
		} else {
			enif_free(io);
			return (enif_make_badarg(env));
		}
	} else {
		enif_free(io);
		return (enif_make_badarg(env));
	}

	if (!enif_inspect_binary(env, argv[2], &bin)) {
		enif_free(io);
		return (enif_make_badarg(env));
	}
	io->pni_data = enif_alloc(bin.size);
	io->pni_len = bin.size;
	bcopy(bin.data, io->pni_data, bin.size);

	enif_mutex_lock(hdl->pnh_mtx);
	if (hdl->pnh_state != PCSC_HDL_IN_TXN &&
	    hdl->pnh_state != PCSC_HDL_CONNECTED) {
		enif_mutex_unlock(hdl->pnh_mtx);
		enif_free(io->pni_data);
		enif_free(io);
		return (enif_make_tuple2(env,
		    enif_make_atom(env, "error"),
		    enif_make_atom(env, "bad_state")));
	}
	if (hdl->pnh_ioq_tail == NULL) {
		hdl->pnh_ioq = io;
		hdl->pnh_ioq_tail = io;
	} else {
		hdl->pnh_ioq_tail->pni_next = io;
		hdl->pnh_ioq_tail = io;
	}
	enif_mutex_unlock(hdl->pnh_mtx);
	enif_cond_signal(hdl->pnh_ioq_cond);

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
	{ "connect", 3, pcsc_nif_connect },
	{ "begin_transaction", 1, pcsc_nif_begin_txn },
	{ "end_transaction", 1, pcsc_nif_end_txn },
	{ "transmit", 3, pcsc_nif_transmit },
	{ "set_disposition", 2, pcsc_nif_set_dispos },
	{ "change_handle_owner", 2, pcsc_nif_change_hdl_owner },
	{ "change_context_owner", 2, pcsc_nif_change_ctx_owner },
	{ "disconnect", 1, pcsc_nif_disconnect }
};

ERL_NIF_INIT(pcsc_nif, nif_funcs, pcsc_nif_load, NULL, NULL, pcsc_nif_unload);
