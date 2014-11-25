/* $Id$ */

/*-
 * Copyright 2010  Morgan Stanley and Co. Incorporated
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef LIBKNC_H
#define LIBKNC_H

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <poll.h>

#include <gssapi/gssapi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The opaque data structure definition:
 */

struct internal_knc_ctx;
typedef struct internal_knc_ctx *knc_ctx;

typedef void (*knc_callback)(knc_ctx);

typedef enum { KNC_DIR_SEND, KNC_DIR_RECV } knc_dir;

/*
 * The various constructors:
 */

knc_ctx		knc_ctx_init(void);
void		knc_ctx_destroy(knc_ctx);
void		knc_ctx_close(knc_ctx);		/* deprecated */

/* Altering and querying the context */

int		knc_get_opt(knc_ctx, unsigned);
void		knc_set_opt(knc_ctx, unsigned, int);

/*
 * These are the ``options''.  Some of them are KNC_SOCK and some are
 * KNC_OPT, this distinguishes those which are directly tied to the
 * corresponding socket options vs. those that affect the protocol that
 * KNC implements.
 *
 * XXXrcd: is this a meaningful distinction?
 */

#define	KNC_SOCK_NONBLOCK		0x0001
#define	KNC_SOCK_CLOEXEC		0x0002
#define KNC_OPT_NOPRIVACY		0x0004
#define	KNC_OPT_NOPRIVATE		KNC_OPT_NOPRIVACY
#define KNC_OPT_SENDCMDS		0x0008
#define KNC_OPT_PROC_CTX_TOK_WORKS	0x0009

/* The following options are ints rather than boolean */

#define KNC_OPT_SENDINBUFSIZ	0x8001
#define KNC_OPT_RECVINBUFSIZ	0x8002

int		knc_is_authenticated(knc_ctx);
void		knc_set_cred(knc_ctx, gss_cred_id_t);
void		knc_set_service(knc_ctx, gss_name_t);
void		knc_import_set_service(knc_ctx, const char *, const gss_OID);
void		knc_import_set_hb_service(knc_ctx, const char *, const char *);
void		knc_set_cb(knc_ctx, gss_channel_bindings_t);
void		knc_set_req_mech(knc_ctx, gss_OID);
gss_OID		knc_get_ret_mech(knc_ctx);
void		knc_set_req_flags(knc_ctx, OM_uint32);
OM_uint32	knc_get_ret_flags(knc_ctx);
void		knc_set_time_req(knc_ctx, OM_uint32);
OM_uint32	knc_get_time_rec(knc_ctx);
gss_name_t	knc_get_client(knc_ctx);
gss_name_t	knc_get_service(knc_ctx);
gss_cred_id_t	knc_get_deleg_cred(knc_ctx);
void		knc_free_deleg_cred(knc_ctx);
void		knc_set_local_fds(knc_ctx, int, int);
void		knc_set_local_fd(knc_ctx, int);
void		knc_give_local_fds(knc_ctx, int, int);
void		knc_give_local_fd(knc_ctx, int);
int		knc_get_local_rfd(knc_ctx);
int		knc_get_local_wfd(knc_ctx);
void		knc_set_net_fds(knc_ctx, int, int);
void		knc_set_net_fd(knc_ctx, int);
void		knc_give_net_fds(knc_ctx, int, int);
void		knc_give_net_fd(knc_ctx, int);
int		knc_get_net_rfd(knc_ctx);
int		knc_get_net_wfd(knc_ctx);
nfds_t		knc_get_pollfds(knc_ctx, struct pollfd *, knc_callback *,
				nfds_t);
void		knc_service_pollfds(knc_ctx, struct pollfd *, knc_callback *,
				    nfds_t);
void		knc_set_debug(knc_ctx, int);
void		knc_set_debug_prefix(knc_ctx, const char *);

/* Error handling */

int		 knc_error(knc_ctx);
const char	*knc_errstr(knc_ctx);

/* Establishing the connexion */

void		knc_initiate(knc_ctx);
void		knc_accept(knc_ctx);

/* Helper functions for establishing connexions */

knc_ctx		knc_connect(knc_ctx, const char *, const char *,
			    const char *, int);

/* The simple(?) interface */

void		knc_authenticate(knc_ctx);
ssize_t		knc_read(knc_ctx, void *, size_t);
ssize_t		knc_fullread(knc_ctx, void *, size_t);
ssize_t		knc_write(knc_ctx, const void *, size_t);
int		knc_shutdown(knc_ctx, int);
int		knc_close(knc_ctx);
int		knc_eof(knc_ctx);
int		knc_io_complete(knc_ctx);
int		knc_fill(knc_ctx, int);
int		knc_flush(knc_ctx, int, size_t);
void		knc_garbage_collect(knc_ctx);

/*
 * The buffer interface allows programmers to use KNC as a simple byte
 * stream without worrying about file descriptors.
 */

#define KNC_DIR_RECV	0x1
#define KNC_DIR_SEND	0x2

int		knc_put_eof(knc_ctx, int);
size_t		knc_put_buf(knc_ctx, int, const void *,  size_t);
size_t		knc_put_ubuf(knc_ctx, int, void *, size_t,
			     void (*)(void *, void *), void *);
ssize_t		knc_put_mmapbuf(knc_ctx, int, size_t, int, int, off_t);
size_t		knc_get_ibuf(knc_ctx, int, void **, size_t);
size_t		knc_get_obuf(knc_ctx, int, void **, size_t);
size_t		knc_get_obufv(knc_ctx, int, int, struct iovec **, int *);
size_t		knc_get_obufc(knc_ctx, int, void **, size_t);
size_t		knc_drain_buf(knc_ctx, int, size_t);
size_t		knc_fill_buf(knc_ctx, int, size_t);
size_t		knc_avail(knc_ctx, int);
size_t		knc_pending(knc_ctx, int);
int		knc_need_input(knc_ctx, int);
int		knc_can_output(knc_ctx, int);

#ifdef __cplusplus
}
#endif

#endif /* defined(LIBKNC_H) */
