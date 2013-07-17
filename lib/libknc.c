/* */

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

#include "config.h"

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#if HAVE_GSSAPI_H
#include <gssapi.h>
#else
#if HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#else
#include <gssapi/gssapi_krb5.h>
#endif
#endif

#include "libknc.h"

struct knc_stream_bit {
	void			 *buf;
	void			(*free)(void *, void *);
	void			 *cookie;
	struct knc_stream_bit	 *next;
	size_t			  len;
	size_t			  allocated;
};

struct knc_stream_gc {
	void			*ptr;
	struct knc_stream_gc	*next;
};

struct knc_stream {
	struct knc_stream_bit	*head;
	struct knc_stream_bit	*cur;
	struct knc_stream_bit	*tail;
	struct knc_stream_gc	*garbage;
	size_t			 bufpos;
	size_t			 avail;
	char			*failed_func;
	int			 errnum;
};

#define KNC_STREAM_ERROR(s, d, r)	\
	do {				\
		(s)->failed_func = (d);	\
		(s)->errnum = errno;	\
		return (r);		\
	} while (0/*CONSTCOND*/)

struct knc_ctx {
	/* GSS input/output data */
	gss_ctx_id_t		 gssctx;
	gss_cred_id_t		 cred;		/* both */
	gss_channel_bindings_t	 cb;		/* both */
	gss_OID			 req_mech;	/* request mech (initiator) */
	gss_OID			 ret_mech;	/* returned mech (both) */
	gss_name_t		 client;	/* acceptor only; we own */
	gss_name_t		 service;	/* initiator only */
	gss_name_t		 imp_service;	/* initiator only; we own */
	gss_name_t		 inq_service;	/* both; we own */
	OM_uint32		 req_flags;	/* initiator */
	OM_uint32		 ret_flags;	/* both */
	OM_uint32		 time_req;	/* initiator */
	OM_uint32		 time_rec;	/* both */
	gss_cred_id_t		 deleg_cred;	/* acceptor */

	/* Connexion state data */
	int			 opts;

	int			 locally_initiated;
	int			 open;
#define OPEN_READ	0x10
#define OPEN_WRITE	0x20
	int			 state;
#define STATE_UNKNOWN	0x0
#define STATE_ACCEPT	0x1
#define STATE_INIT	0x2
#define STATE_SESSION	0x3
#define STATE_COMMAND	0x4
	int			 error;
	int			 errnum;
	int			 debug;
#define KNC_ERROR_GSS		0x1
#define KNC_ERROR_PROTO		0x2
#define KNC_ERROR_RST		0x3
#define KNC_ERROR_PIPE		0x4
#define KNC_ERROR_NOCTX		0x5
#define KNC_ERROR_ENOMEM	0x6
#define KNC_ERROR_GENERIC	0x7
	char			*errstr;

	size_t			 recvinbufsiz;	/* XXXrcd: low water? */
	size_t			 sendinbufsiz;	/* XXXrcd: low water? */

	size_t			 sendmax;	/* XXXrcd: hmmm */
	size_t			 gssmaxpacket;

	struct knc_stream	 raw_recv;
	struct knc_stream	 cooked_recv;
	struct knc_stream	 raw_send;
	struct knc_stream	 cooked_send;

	/*
	 * These are the read/write/close functions, they will be executed
	 * at the correct time by the code if they are defined.  If they
	 * are not defined, they will not be executed.
	 */

	int	  net_uses_fd;
	int	  net_is_open;
	void	 *netcookie;
	ssize_t	(*netread)(void *, void *, size_t);
	ssize_t	(*netwritev)(void *, const struct iovec *, int);
	int	(*netclose)(void *);

	int	  local_uses_fd;
	int	  local_is_open;
	void	 *localcookie;
	ssize_t	(*localread)(void *, void *, size_t);
	ssize_t	(*localwritev)(void *, const struct iovec *, int);
	int	(*localclose)(void *);
};

struct fd_cookie {
	int	mine;
	int	rfd;
	int	wfd;
};

/* mmm, macros. */

#define KNC_GSS_ERROR(_ctx, _maj, _min, _ret, _str) do {		\
		if (GSS_ERROR((_maj))) {				\
			knc_gss_error((_ctx), (_maj), (_min), (_str));	\
			return _ret;					\
		}							\
	} while (0/*CONSTCOND*/)

#define MIN(a, b)	((a)<(b)?(a):(b))

/* XXXrcd: eventually get rid of DEBUG() */
/* XXXnico: debug should be a part of the ctx and streams, not a global */
/* XXXnico: also, might as well put error info in streams as well */
int debug = 0;
#define DEBUG(x) do {				\
		if (debug) {			\
			debug_printf x ;	\
		}				\
	} while (0/*CONSTCOND*/)

#define KNCDEBUG(c, x) do {			\
		if ((c)->debug) {		\
			debug_printf x ;	\
		}				\
	} while (0/*CONSTCOND*/)

/* Local function declarations */

static void	debug_printf(const char *, ...)
    __attribute__((__format__(__printf__, 1, 2)));

static void	knc_generic_error(knc_ctx, const char *);
static void	knc_syscall_error(knc_ctx, const char *, int);
static void	knc_enomem(knc_ctx);
static void	knc_gss_error(knc_ctx, OM_uint32, OM_uint32, const char *);

static struct knc_stream_bit	*knc_alloc_stream_bit(size_t);
static size_t			 knc_append_stream_bit(struct knc_stream *,
				    struct knc_stream_bit *);

static int	knc_stream_error(knc_ctx, struct knc_stream *);
static size_t	knc_put_stream(struct knc_stream *, const void *, size_t);
static size_t	knc_put_stream_gssbuf(struct knc_stream *, gss_buffer_t);
static size_t	knc_get_istream(struct knc_stream *, void **, size_t);
static size_t	knc_get_ostream(struct knc_stream *, void **, size_t);
static size_t	knc_get_ostreamv(struct knc_stream *, struct iovec **, int *);
static int	knc_stream_put_trash(struct knc_stream *, void *);
static size_t	knc_get_ostream_contig(struct knc_stream *, void **, size_t);
static ssize_t	knc_stream_drain(struct knc_stream *, size_t);
static ssize_t	knc_stream_fill(struct knc_stream *, size_t);
static size_t	knc_stream_avail(struct knc_stream *);
static void	knc_stream_garbage_collect(struct knc_stream *);

static int	socket_options(int, int);
static size_t	read_packet(struct knc_stream *, void **b);
static size_t	put_packet(struct knc_stream *, gss_buffer_t);

static int	knc_state_init(knc_ctx, void *, size_t);
static int	knc_state_accept(knc_ctx, void *, size_t);
static int	knc_state_session(knc_ctx, void *, size_t);
static int	knc_state_command(knc_ctx, void *, size_t);
static int	knc_state_process_in(knc_ctx);
static int	knc_state_process_out(knc_ctx);

static struct knc_stream *knc_find_buf(knc_ctx, int, int);

/* And, ta da: the code */

void
debug_printf(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%d: ", getpid());
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void
knc_destroy_stream(struct knc_stream *s)
{

	if (!s)
		return;

	s->cur = NULL;
	knc_stream_garbage_collect(s);
}

static size_t
knc_append_stream_bit(struct knc_stream *s, struct knc_stream_bit *b)
{

	b->next   = NULL;

	s->avail += b->len;
	if (s->head == NULL) {
		s->head = s->cur = s->tail = b;
		s->bufpos = 0;
	} else {
		s->tail->next = b;
		s->tail = b;
	}

	if (!s->cur)
		s->cur = s->tail;

	return b->len;
}

#define STREAM_BIT_ALLOC_UNIT	(64 * 1024)

static struct knc_stream_bit *
knc_alloc_stream_bit(size_t len)
{
	struct knc_stream_bit	*bit;
	char			*tmpbuf;

	len  = len / STREAM_BIT_ALLOC_UNIT + (len % STREAM_BIT_ALLOC_UNIT)?1:0;
	len *= STREAM_BIT_ALLOC_UNIT;
	len  = MIN((2 * STREAM_BIT_ALLOC_UNIT), len);

	bit = calloc(1, sizeof(*bit));
	if (!bit)
		return NULL;

	tmpbuf = calloc(len, 1);
	if (!tmpbuf) {
		free(bit);
		return NULL;
	}

	bit->buf       = tmpbuf;
	bit->len       = 0;
	bit->allocated = len;

	return bit;
}

static size_t
knc_put_stream(struct knc_stream *s, const void *buf, size_t len)
{
	void	*newbuf;
	size_t	 ret;
	size_t	 total = 0;

	while (len > 0) {
		ret = knc_get_istream(s, &newbuf, len);

		if (!ret)
			/* malloc failed: stop */
			break;

		memcpy(newbuf, buf, ret);
		knc_stream_fill(s, ret); /* XXXnico: check for errors */

		len   -= ret;
		total += ret;
	}

	return total;
}

static size_t
knc_put_stream_userbuf(struct knc_stream *s, void *buf, size_t len,
		       void (*callback)(void *, void *), void *cookie)
{
	struct knc_stream_bit	*bit;

	bit = calloc(1, sizeof(*bit));
	if (!bit)
		KNC_STREAM_ERROR(s, "calloc", 0);

	bit->buf	= buf;
	bit->allocated	= len;
	bit->len	= len;
	bit->free	= callback;
	bit->cookie	= cookie;

	return knc_append_stream_bit(s, bit);
}

/*ARGSUSED*/
static void
free_gssbuf(void *buf, void *cookie)
{
	OM_uint32	min;

	gss_release_buffer(&min, cookie);
	free(cookie);
}

static size_t
knc_put_stream_gssbuf(struct knc_stream *s, gss_buffer_t inbuf)
{
	gss_buffer_t	buf;

	buf = calloc(1, sizeof(*buf));
	if (!buf)
		KNC_STREAM_ERROR(s, "calloc", 0);

	buf->value  = inbuf->value;
	buf->length = inbuf->length;

	return knc_put_stream_userbuf(s, buf->value, buf->length, free_gssbuf,
	    buf);
}

struct mmapregion {
	void	*buf;
	size_t	 len;
};

/*ARGSUSED*/
static void
free_mmapbuf(void *buf, void *cookie)
{
	struct mmapregion	*r = cookie;

	munmap(r->buf, r->len);
	free(r);
}

static size_t
knc_put_stream_mmapbuf(struct knc_stream *s, size_t len, int flags, int fd,
		       off_t offset)
{
	struct mmapregion	*r;

	r = calloc(1, sizeof(*r));
	if (!r)
		KNC_STREAM_ERROR(s, "calloc", 0);

	r->buf = mmap(NULL, len, PROT_READ, flags, fd, offset);
	r->len = len;

	if (!r->buf)
		KNC_STREAM_ERROR(s, "mmap", 0);

	return knc_put_stream_userbuf(s, r->buf, r->len, free_mmapbuf, r);
}

static size_t
knc_get_istream(struct knc_stream *s, void **buf, size_t len)
{
	struct knc_stream_bit	*tmp;
	size_t			 remaining;

	if (!s) {
		/* XXXrcd: better errors... */
		return 0;
	}

	if (s->tail) {
		remaining = s->tail->allocated - s->tail->len;

		if (remaining >= len) {
			*buf = (void *)((char *)s->tail->buf + s->tail->len);
			return MIN(len, remaining);
		}
	}

	tmp = knc_alloc_stream_bit(len);
	if (!tmp)
		KNC_STREAM_ERROR(s, "calloc", 0);

	knc_append_stream_bit(s, tmp);

	*buf = tmp->buf;
	return MIN(len, tmp->allocated);
}

/*
 * knc_get_ostream specifically only returns a single knc_stream_bit.
 * knc_get_ostream returns a ptr into its data structure, the caller
 * may not modify it.  This allows the caller to construct an iovec
 * for writing.
 */

static size_t
knc_get_ostream(struct knc_stream *s, void **buf, size_t len)
{

	if (!s || !s->cur)
		/* Nothing here... */
		return 0;

	DEBUG(("knc_get_ostream: s->cur = %p\n", s->cur));

	/* XXXrcd: hmmm, what if bufpos moves us beyond the stream? */

	if (s->cur->len >= s->bufpos) {
		*buf = (char *)s->cur->buf + s->bufpos;
		return MIN(len, s->cur->len - s->bufpos);
	}

	return 0;
}

#define MAX_IOVCNT	32

static size_t
knc_get_ostreamv(struct knc_stream *s, struct iovec **vec, int *count)
{
	struct knc_stream_bit	*cur;
	size_t			 i;
	size_t			 len;

	if (!s || !s->cur)
		/* Nothing here */
		return 0;

	/* First we count the bits. */

	i = 0;
	for (cur = s->cur; cur; cur = cur->next)
		/* XXXrcd: test length and all of that? */
		if (i++ == MAX_IOVCNT)
			break;

	*vec = malloc(i * sizeof(**vec));
	if (!*vec)
		KNC_STREAM_ERROR(s, "malloc", 0);

	i = 0;
	len = 0;
	cur = s->cur;

	(*vec)[i  ].iov_base = (char *)cur->buf + s->bufpos;
	(*vec)[i++].iov_len  = cur->len - s->bufpos;
	len += cur->len - s->bufpos;
	DEBUG(("creating iovec element of length %zu, total %zu\n",
	    len, len));

	for (cur = cur->next; cur; cur = cur->next) {
		(*vec)[i].iov_base = cur->buf;
		(*vec)[i].iov_len  = cur->len;
		len += cur->len;
		DEBUG(("creating iovec element of length %zu, "
		    "total %zu\n", cur->len, len));
		if (i++ == MAX_IOVCNT)
			break;
	}

	*count = (int)i;
	knc_stream_put_trash(s, *vec);

	return len;
}

/*
 * knc_get_ostream_contig() will fetch an entire contiguous newly allocated
 * buffer of the desired length, if it exists.  This may involve copying, but
 * it may not.  The caller is still not allowed to either modify or free(3)
 * the returned buffer.
 */

static size_t
knc_get_ostream_contig(struct knc_stream *s, void **buf, size_t len)
{
	struct knc_stream_bit	*cur;
	size_t			 retlen;
	size_t			 tmplen;

	if (!s || !s->cur)
		return 0;

	/* We adjust len down to the available bytes */

	tmplen = knc_stream_avail(s);
	len = MIN(tmplen, len);

	/*
	 * Then, let's see if we have a single bit that fills this up.
	 * If we do, we can process this request without copying.
	 */

	tmplen = knc_get_ostream(s, buf, len);
	if (tmplen == len)
		return len;

	/* Okay, we're going to have to allocate here. */

	*buf = malloc(len);
	if (*buf == NULL)
		KNC_STREAM_ERROR(s, "malloc", 0);
	knc_stream_put_trash(s, *buf);

	retlen = 0;
	cur = s->cur;

	retlen = cur->len - s->bufpos;
	memcpy(*buf, (char *)cur->buf + s->bufpos, retlen);
	cur = cur->next;

	while (retlen < len) {
		tmplen = MIN(len - retlen, cur->len);
		memcpy((char *)*buf + retlen, cur->buf, tmplen);

		cur = cur->next;
		retlen += tmplen;
	}

	return retlen;
}

static ssize_t
knc_stream_drain(struct knc_stream *s, size_t len)
{

	DEBUG(("knc_stream_drain called with %zu\n", len));

	if (!s->cur)
		return -1;

	/* XXXrcd: sanity */
	DEBUG(("knc_stream_drain(%zu) start: s->cur=%p, avail=%zu bufpos=%zu\n",
	    len, s->cur, s->avail, s->bufpos));

	s->avail  -= len;
	s->bufpos += len;

	while (s->bufpos >= s->cur->len) {
		s->bufpos -= s->cur->len;
		s->cur = s->cur->next;

		if (!s->cur) {
			s->avail = 0;
			s->bufpos = 0;
			break;
		}
	}

	DEBUG(("knc_stream_drain end: s->cur = %p\n", s->cur));

	return len;
}

static ssize_t
knc_stream_fill(struct knc_stream *s, size_t len)
{

	/* XXXrcd: perform sanity */

	if (!s->cur || !s->tail)
		return -1;

	/* We do not have room. */
	if (s->tail->allocated < s->tail->len + len)
		/* XXXrcd: better errors here! */
		return -1;

	s->avail     += len;
	s->tail->len += len;

	return len;
}

static size_t
knc_stream_avail(struct knc_stream *s)
{

	return s->avail;
}

static int
knc_stream_put_trash(struct knc_stream *s, void *ptr)
{
	struct knc_stream_gc	*tmp;

	/*
	 * XXXrcd: we should allocate space for the rubbish before
	 *         we allocate it as if we fail this malloc, we will
	 *         start to leak because we aren't free(3)ing the
	 *         garbage.
	 */

	tmp = malloc(sizeof(*tmp));
	if (!tmp)
		KNC_STREAM_ERROR(s, "calloc", -1);

	tmp->ptr = ptr;
	tmp->next = s->garbage;
	s->garbage = tmp;

	return 0;
}

/*
 * knc_stream_garbage_collect is provided because knc_get_ostream does
 * not actually deallocate the memory that is associated with it.
 * knc_clean_buf() will deallocate all memory between head and cur.
 */

static void
knc_stream_garbage_collect(struct knc_stream *s)
{
	struct knc_stream_bit	*tmpbit;
	struct knc_stream_gc	*gc;
	struct knc_stream_gc	*tmpgc;

	if (!s)
		return;

	while (s->head && s->head != s->cur) {
		tmpbit = s->head->next;

		if (s->head->free)
			s->head->free(s->head->buf, s->head->cookie);
		else
			free(s->head->buf);

		free(s->head);
		s->head = tmpbit;
	}

	if (!s->head)
		s->tail = s->cur = NULL;

	/* Clean up the refuse that has been allocated */

	for (gc = s->garbage; gc; ) {
		tmpgc = gc;
		gc = gc->next;
		free(tmpgc->ptr);
		free(tmpgc);
	}

	s->garbage = NULL;
}

static size_t
read_packet(struct knc_stream *s, void **buf)
{
	size_t		 len;
	uint32_t	 wirelen;
	void		*tmp;

	DEBUG(("read_packet: enter\n"));

	if (knc_get_ostream_contig(s, &tmp, 4) < 4)
		return 0;

	wirelen = ntohl(*((uint32_t *)tmp));

	DEBUG(("read_packet: got wirelen = %u\n", wirelen));
	if (knc_stream_avail(s) < (size_t)wirelen + 4)
		return 0;

	knc_stream_drain(s, 4);

	/* Okay, now we know that we've got an entire packet */

	DEBUG(("read_packet: getting %u bytes\n", wirelen));
	len = knc_get_ostream_contig(s, buf, wirelen);

	if (len != wirelen)
		abort();	/* XXXrcd: really shouldn't happen. */

	knc_stream_drain(s, len);

	DEBUG(("read_packet: %zu left in stream\n", s->avail));
	/* XXXrcd: broken, I think. */

	return len;
}

static size_t
put_packet(struct knc_stream *s, gss_buffer_t buf)
{
	uint32_t	netlen;

	netlen = htonl((uint32_t)buf->length);
	knc_put_stream(s, &netlen, 4);
	knc_put_stream_gssbuf(s, buf); /* XXXnico: why ignore return? */

	/* XXXrcd: useful to return this?  What about errors? */
	return 0;
}

knc_ctx
knc_ctx_init(void)
{
	knc_ctx	ret;

	ret = calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	/* Set some reasonable defaults */

	ret->gssctx		= GSS_C_NO_CONTEXT;
	ret->client		= GSS_C_NO_NAME;
	ret->service		= GSS_C_NO_NAME;
	ret->imp_service	= GSS_C_NO_NAME;
	ret->inq_service	= GSS_C_NO_NAME;
	ret->cred		= GSS_C_NO_CREDENTIAL;
	ret->cb			= GSS_C_NO_CHANNEL_BINDINGS;
	ret->req_mech   	= GSS_C_NO_OID;
	ret->ret_mech   	= GSS_C_NO_OID;
	ret->req_flags		= GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG;
	ret->deleg_cred		= GSS_C_NO_CREDENTIAL;

	ret->open = OPEN_READ|OPEN_WRITE;
	ret->locally_initiated	= 0;

	ret->recvinbufsiz = 16384;
	ret->sendinbufsiz = 16384;
	ret->sendmax      = 65536;
	ret->gssmaxpacket = 8192;

	return ret;
}

void
knc_set_debug(knc_ctx ctx, int setting)
{

	ctx->debug = setting;
}

void
knc_ctx_close(knc_ctx ctx)
{
	OM_uint32	min;

	if (!ctx)
		return;

	/* We only own the deleg cred */
	gss_release_cred(&min, &ctx->deleg_cred);

	/* We always own ctx->client */
	gss_release_name(&min, &ctx->client);

	/* We don't own ctx->service */
	gss_release_name(&min, &ctx->imp_service);
	gss_release_name(&min, &ctx->inq_service);

	/* We always own the security context */
	gss_delete_sec_context(&min, &ctx->gssctx, GSS_C_NO_BUFFER);

	/* The caller owns the channel bindings */

	if (ctx->net_is_open && ctx->netclose)
		(ctx->netclose)(ctx->netcookie);

	if (ctx->local_is_open && ctx->localclose)
		(ctx->localclose)(ctx->localcookie);

	/* XXXrcd: memory leaks?  */
	/* XXXnico: smartass comment: use valgrind ;) */

	free(ctx->errstr);

	knc_destroy_stream(&ctx->raw_recv);
	knc_destroy_stream(&ctx->cooked_recv);
	knc_destroy_stream(&ctx->raw_send);
	knc_destroy_stream(&ctx->cooked_send);

	free(ctx);
}

int
knc_error(knc_ctx ctx)
{

	if (!ctx)
		return KNC_ERROR_NOCTX;

	return ctx->error;
}

const char *
knc_errstr(knc_ctx ctx)
{

	if (!ctx)
		return "No KNC context.";

	if (!ctx->error)
		return NULL;

	if (ctx->errstr)
		return ctx->errstr;

	switch (ctx->error) {
	case KNC_ERROR_ENOMEM:
		return "Out of memory";

	default:
		break;
	}

	return "Could not allocate memory to report error, malloc(3) failed.";
}

int
knc_get_opt(knc_ctx ctx, unsigned opt)
{

	switch (opt) {
	case KNC_OPT_NOPRIVACY:
		return (ctx->opts & KNC_OPT_NOPRIVACY) ? 1 : 0;
	default:
		break;
	}

	return -1;
}

void
knc_set_opt(knc_ctx ctx, unsigned opt, int value)
{
	int	rfd;
	int	wfd;

	if (!ctx)
		return;

	switch (opt) {
	/* We handle all of the flag-options together: */
	case KNC_OPT_NOPRIVACY:
	case KNC_SOCK_NONBLOCK:
	case KNC_SOCK_CLOEXEC:
		if (value)
			ctx->opts |= opt;
		else
			ctx->opts &= ~opt;
		break;

	/* We haven't defined any non-flag options, yet... */

	default:
		break;
	}

	/* Some options require additional actions: */

	switch (opt) {
	case KNC_SOCK_NONBLOCK:
	case KNC_SOCK_CLOEXEC:
		if (ctx->net_uses_fd) {
			rfd = ((struct fd_cookie *)ctx->netcookie)->rfd;
			wfd = ((struct fd_cookie *)ctx->netcookie)->wfd;

			socket_options(rfd, ctx->opts);
			if (wfd != rfd)
				socket_options(wfd, ctx->opts);
		}
		/* XXXrcd: should we do something with the local side?? */
		break;
	default:
		break;
	}
}

int
knc_is_authenticated(knc_ctx ctx)
{

	if (!ctx)
		return 0;

	return ctx->state == STATE_SESSION || ctx->state == STATE_COMMAND;
}

void
knc_set_cred(knc_ctx ctx, gss_cred_id_t cred)
{

	if (!ctx)
		return;

	ctx->cred = cred;
}

void
knc_set_service(knc_ctx ctx, gss_name_t service)
{

	if (!ctx)
		return;

	ctx->service = service;
}

void
knc_import_set_service(knc_ctx ctx, const char *service, const gss_OID nt)
{
	gss_buffer_desc	 name;
	OM_uint32	 maj, min;

	if (!ctx)
		return;

	if (knc_is_authenticated(ctx))
		return;

	name.length = strlen(service);
	name.value  = strdup(service);	/* strdup to avoid const lossage */

	if (!name.value) {
		knc_enomem(ctx);
		return;
	}

	maj = gss_import_name(&min, &name, nt, &ctx->imp_service);
	ctx->service = ctx->imp_service;

	free(name.value);

	/* ??? XXXrcd: L4M3! */
	/* XXXnico: er, so make this return something other than void?! */
	KNC_GSS_ERROR(ctx, maj, min,, "gss_import_name");
}

void
knc_import_set_hb_service(knc_ctx ctx, const char *hostservice,
			  const char *defservice)
{
	char	*hbservice;
	char	*tmp;

	if (!ctx)
		return;

	tmp = strchr(hostservice, '@');
	if (tmp) {
		knc_import_set_service(ctx, hostservice,
		    GSS_C_NT_HOSTBASED_SERVICE);
		return;
	}

	hbservice = malloc(strlen(hostservice) + strlen(defservice) + 2);
	if (!hbservice) {
		knc_enomem(ctx);
		return;
	}

	sprintf(hbservice, "%s@%s", defservice, hostservice);

	knc_import_set_service(ctx, hbservice, GSS_C_NT_HOSTBASED_SERVICE);
	free(hbservice);
}

void
knc_set_cb(knc_ctx ctx, gss_channel_bindings_t cb)
{

	if (!ctx)
		return;

	/* XXXrcd: caller frees? */
	/* XXXnico: yes; we could dup it though... */

	ctx->cb = cb;
}

void
knc_set_req_mech(knc_ctx ctx, gss_OID req_mech)
{

	if (!ctx)
		return;

	ctx->req_mech = req_mech;
}

gss_OID
knc_get_ret_mech(knc_ctx ctx)
{

	if (!ctx)
		return GSS_C_NO_OID;

	return ctx->ret_mech;
}

void
knc_set_req_flags(knc_ctx ctx, OM_uint32 req_flags)
{

	if (!ctx || knc_is_authenticated(ctx))
		return;

	/* XXXrcd: more sanity: are we an initiator? */
	/* XXXrcd: really, we shouldn't allow after we've begun to auth */

	ctx->req_flags = req_flags;
}

OM_uint32
knc_get_ret_flags(knc_ctx ctx)
{

	if (!ctx)
		return 0;

	return ctx->ret_flags;
}

void
knc_set_time_req(knc_ctx ctx, OM_uint32 time_req)
{

	if (!ctx || knc_is_authenticated(ctx))
		return;

	/* XXXrcd: sanity: are we an initiator? */
	/* XXXrcd: really, we shouldn't allow after we've begun to auth */

	ctx->time_req = time_req;
}

OM_uint32
knc_get_time_rec(knc_ctx ctx)
{

	if (!ctx || !knc_is_authenticated(ctx))
		return 0;

	return ctx->time_rec;
}

gss_name_t
knc_get_client(knc_ctx ctx)
{
	OM_uint32	 maj;
	OM_uint32	 min;

	if (!ctx || !knc_is_authenticated(ctx))
		return GSS_C_NO_NAME;

	if (ctx->client != GSS_C_NO_NAME || !ctx->locally_initiated)
	    return ctx->client;

	if (ctx->client == GSS_C_NO_NAME) {
		maj = gss_inquire_context(&min, ctx->gssctx, &ctx->client,
		    NULL, NULL, NULL, NULL, NULL, NULL);
		KNC_GSS_ERROR(ctx, maj, min, GSS_C_NO_NAME,
		    "gss_inquire_context");
	}

	return ctx->client;
}

gss_name_t
knc_get_service(knc_ctx ctx)
{
	OM_uint32	 maj;
	OM_uint32	 min;

	if (!ctx || !knc_is_authenticated(ctx))
		return GSS_C_NO_NAME;

	if (ctx->inq_service == GSS_C_NO_NAME && ctx->locally_initiated) {
		maj = gss_inquire_context(&min, ctx->gssctx, NULL,
		    &ctx->inq_service, NULL, NULL, NULL, NULL, NULL);
		KNC_GSS_ERROR(ctx, maj, min, GSS_C_NO_NAME,
		    "gss_inquire_context");
	}

	return ctx->inq_service;
}

gss_cred_id_t
knc_get_deleg_cred(knc_ctx ctx)
{

	if (!ctx)
		return GSS_C_NO_CREDENTIAL;

	return ctx->deleg_cred;
}

void
knc_free_deleg_cred(knc_ctx ctx)
{
	OM_uint32 min;

	if (!ctx)
		return;

	gss_release_cred(&min, &ctx->deleg_cred);
	return;
}

/* XXXrcd: deal with all the flags */

void
knc_accept(knc_ctx ctx)
{

	if (!ctx)
		return;

	/* XXXrcd: sanity! */

	ctx->gssctx = GSS_C_NO_CONTEXT;
	ctx->state  = STATE_ACCEPT;
}

static int
knc_state_init(knc_ctx ctx, void *buf, size_t len)
{
	gss_buffer_desc	in;
	gss_buffer_desc	out;
	OM_uint32	maj;
	OM_uint32	min;

	in.value  = buf;
	in.length = len;

	out.length = 0;

	KNCDEBUG(ctx, ("knc_state_init: enter\n"));
	ctx->locally_initiated = 1;
	maj = gss_init_sec_context(&min, ctx->cred, &ctx->gssctx,
	    ctx->service, ctx->req_mech, ctx->req_flags, ctx->time_req,
	    ctx->cb, &in, &ctx->ret_mech, &out, &ctx->ret_flags,
	    &ctx->time_rec);

	if (out.length > 0) {
		put_packet(&ctx->cooked_send, &out);
		/*
		 * If put_packet() fails the app will find out with
		 * knc_error()
		 */
		knc_stream_error(ctx, &ctx->cooked_send);
	}

	KNC_GSS_ERROR(ctx, maj, min, -1, "gss_init_sec_context");

	if (!(maj & GSS_S_CONTINUE_NEEDED))
		ctx->state = STATE_SESSION;

	return 0;
}

static int
knc_state_accept(knc_ctx ctx, void *buf, size_t len)
{
	gss_buffer_desc	 in;
	gss_buffer_desc	 out;
	OM_uint32	 maj;
	OM_uint32	 min;

	/* Sanity, probably unnecessary */
	if (ctx->state != STATE_ACCEPT)
		return -1;

	KNCDEBUG(ctx, ("knc_state_accept: enter\n"));

	out.length = 0;

	in.value  = buf;
	in.length = len;

	maj = gss_accept_sec_context(&min, &ctx->gssctx, ctx->cred, &in,
	    ctx->cb, &ctx->client, &ctx->ret_mech, &out,
	    &ctx->ret_flags, &ctx->time_rec, &ctx->deleg_cred);

	if (out.length) {
		put_packet(&ctx->cooked_send, &out);
		knc_stream_error(ctx, &ctx->cooked_send);
	}

	KNC_GSS_ERROR(ctx, maj, min, -1, "gss_accept_sec_context");

	if (!(maj & GSS_S_CONTINUE_NEEDED))
		ctx->state = STATE_SESSION;

	return 0;
}

static int
knc_state_session(knc_ctx ctx, void *buf, size_t len)
{
	gss_buffer_desc	in;
	gss_buffer_desc	out;
	OM_uint32	maj;
	OM_uint32	min;

	in.value  = buf;
	in.length = len;

	out.length = 0;

	KNCDEBUG(ctx, ("knc_state_session: enter\n"));
	maj = gss_unwrap(&min, ctx->gssctx, &in, &out, NULL, NULL);

	if (maj != GSS_S_COMPLETE) {
		knc_gss_error(ctx, maj, min, "gss_unwrap");
		return -1;
	}

	if (out.length == 0) {
		ctx->state = STATE_COMMAND;
		return 0;
	}

	knc_put_stream_gssbuf(&ctx->cooked_recv, &out);

	return 0;
}

static int
knc_state_command(knc_ctx ctx, void *buf, size_t len)
{
	gss_buffer_desc	in;
	gss_buffer_desc	out;
	OM_uint32	maj;
	OM_uint32	min;

	in.value  = buf;
	in.length = len;

	out.length = 0;

	KNCDEBUG(ctx, ("knc_state_command: enter\n"));
	maj = gss_unwrap(&min, ctx->gssctx, &in, &out, NULL, NULL);

	/* XXXrcd: better error handling... */
	if (maj != GSS_S_COMPLETE) {
		knc_gss_error(ctx, maj, min, "gss_unwrap");
		return -1;
	}

	if (out.length == 0) {
		/* Close the stream for reading... */
		ctx->open &= ~(OPEN_READ|OPEN_WRITE);
	}

	/*
	 * XXXrcd: unknown command.  should we continue?  yes, for now.
	 *         Nico wants to return an error to the other side, we
	 *         will implement that before the release.  To do this,
	 *         we should like number the commands so that the other
	 *         end knows which one we are not implementing.  This
	 *         will require that some structure be defined for the
	 *         commands in advance of the first release...
	 */
	/*
	 * XXXnico: So why not send two zero-length tokens in response
	 *	    for now?  We don't know what to do with commands.
	 *	    We expect that the next token will have command
	 *	    data.  Assuming that each future command will have a
	 *	    command response, all we need to do is process them
	 *	    in order.  But even if we need XIDs so we can
	 *	    process them out of order, a pair of zero-length
	 *	    tokens should always suffice as a "don't know what
	 *	    you're talking about" response: the peer can count
	 *	    up these responses and match up actual responses to
	 *	    requests and infer which requests were responded to
	 *	    with "no clue man".  That's what I implemented
	 *	    below.
	 */

	ctx->state = STATE_SESSION;
	return 0;
}

static int
knc_state_process_in(knc_ctx ctx)
{
	void	*buf;
	size_t	 len;
	int	 ret;

	KNCDEBUG(ctx, ("knc_state_process_in: enter\n"));

	/*
	 * We have two main flows in which we are interested, input
	 * and output.  So, we check to see what is on each queue and
	 * if we can make progress.
	 *
	 * First we process the read side.  Let's see if we have a
	 * packet.
	 */

	for (;;) {
		len = read_packet(&ctx->raw_recv, &buf);

		KNCDEBUG(ctx, ("read_packet returned %zd\n", len));

		if (len < 1)	/* XXXrcd: How about 0? */
			return 0;

		switch (ctx->state) {
		case STATE_ACCEPT:
			ret = knc_state_accept(ctx, buf, len);
			break;
		case STATE_INIT:
			ret = knc_state_init(ctx, buf, len);
			break;
		case STATE_SESSION:
			ret = knc_state_session(ctx, buf, len);
			break;
		case STATE_COMMAND:
			ret = knc_state_command(ctx, buf, len);
			break;
		default:
			ret = -1;
			break;
		}

		/* XXXrcd: errors and the like? */

	}

	/*NOTREACHED*/
	return ret;
}

static int
knc_state_process_out(knc_ctx ctx)
{
	gss_buffer_desc	 in;
	gss_buffer_desc	 out;
	OM_uint32	 maj;
	OM_uint32	 min;
	size_t		 len;
	void		*buf;
	int		 privacy = (ctx->opts & KNC_OPT_NOPRIVACY)?0:1;

	KNCDEBUG(ctx, ("knc_state_process_out: enter\n"));

	/*
	 * We only process our out buffer if we have established the
	 * GSSAPI connexion because the handshake routines write directly
	 * to ctx->cooked_send.
	 */

	if (ctx->state == STATE_COMMAND) {
		/* XXXnico: Yeah, manually unrolled loop of two go arounds */
		in.length = 0;
		in.value  = NULL;
		maj = gss_wrap(&min, ctx->gssctx, privacy, GSS_C_QOP_DEFAULT,
		    &in, NULL, &out);

		KNC_GSS_ERROR(ctx, maj, min, -1, "gss_wrap");

		put_packet(&ctx->cooked_send, &out);
		knc_stream_error(ctx, &ctx->cooked_send);

		in.length = 0;
		in.value  = NULL;
		maj = gss_wrap(&min, ctx->gssctx, privacy, GSS_C_QOP_DEFAULT,
		    &in, NULL, &out);

		KNC_GSS_ERROR(ctx, maj, min, -1, "gss_wrap");

		put_packet(&ctx->cooked_send, &out);
		knc_stream_error(ctx, &ctx->cooked_send);
		ctx->state = STATE_SESSION;
	}

	if (ctx->state != STATE_SESSION)
		return 0;

	while (knc_stream_avail(&ctx->cooked_send) < ctx->sendmax) {

		/*
		 * We clip the length at ctx->gssmaxpacket to make
		 * the job of the receiver easier.
		 */

		len = knc_get_ostream_contig(&ctx->raw_send, &buf,
		    ctx->gssmaxpacket);

		if (len < 1) {
			/* XXXrcd: ERRORS? Maybe there aren't any...? */
			return 0;
		}

		in.length = len;
		in.value  = buf;
		maj = gss_wrap(&min, ctx->gssctx, privacy, GSS_C_QOP_DEFAULT,
		    &in, NULL, &out);

		KNC_GSS_ERROR(ctx, maj, min, -1, "gss_wrap");

		put_packet(&ctx->cooked_send, &out);
		knc_stream_error(ctx, &ctx->cooked_send);
		knc_stream_drain(&ctx->raw_send, len);
	}

	KNCDEBUG(ctx, ("knc_state_process_out: leave\n"));

	return 0;
}

#define KNC_SIDE_IN	0x100
#define KNC_SIDE_OUT	0x200

static struct knc_stream *
knc_find_buf(knc_ctx ctx, int side, int dir)
{
	struct knc_stream	*s;

	switch (side | dir) {
	case KNC_DIR_RECV|KNC_SIDE_OUT:
		s = &ctx->cooked_recv;
		break;
	case KNC_DIR_RECV|KNC_SIDE_IN:
		s = &ctx->raw_recv;
		break;
	case KNC_DIR_SEND|KNC_SIDE_OUT:
		s = &ctx->cooked_send;
		break;
	case KNC_DIR_SEND|KNC_SIDE_IN:
		s = &ctx->raw_send;
		break;
	default:
		/* XXXrcd: huh? Maybe this should be abort()? */
		s = NULL;
		break;
	}

	return s;
}

size_t
knc_put_buf(knc_ctx ctx, int dir, const void *buf, size_t len)
{
	struct knc_stream *s;

	if (!ctx)
		return 0;

	s = knc_find_buf(ctx, KNC_SIDE_IN, dir);
	if (!s) {
		knc_generic_error(ctx, "no matching stream");
		return 0;
	}
	return knc_put_stream(knc_find_buf(ctx, KNC_SIDE_IN, dir), buf, len);
}

size_t
knc_put_ubuf(knc_ctx ctx, int dir, void *buf, size_t len,
	     void (*callback)(void *, void *), void *cookie)
{

	if (!ctx) {
		/* XXXrcd: should probably call the callback to free things. */
		return 0;
	}

	return knc_put_stream_userbuf(knc_find_buf(ctx, KNC_SIDE_IN, dir),
	    buf, len, callback, cookie);
}

size_t
knc_put_mmapbuf(knc_ctx ctx, int dir, size_t len, int flags, int fd,
		off_t offset)
{
	struct knc_stream *s;
	size_t ret;

	if (!ctx) {
		/* XXXrcd: should probably call the callback to free things. */
		/* XXXnico: huh? what callback? there's no ctx to one from! */
		return 0;
	}

	s = knc_find_buf(ctx, KNC_SIDE_IN, dir);
	ret = knc_put_stream_mmapbuf(s, len, flags, fd, offset);
	knc_stream_error(ctx, s);
	return ret;
}

size_t
knc_get_ibuf(knc_ctx ctx, int dir, void **buf, size_t len)
{
	struct knc_stream *s;
	size_t ret = 0;

	if (!ctx)
		return 0;

	s = knc_find_buf(ctx, KNC_SIDE_IN, dir);
	if (!s)
		knc_generic_error(ctx, "no matching stream");
	else
		ret = knc_get_istream(s, buf, len);
	knc_stream_error(ctx, s);
	return ret;
}

size_t
knc_get_obuf(knc_ctx ctx, int dir, void **buf, size_t len)
{

	if (!ctx)
		return 0;

	return knc_get_ostream(knc_find_buf(ctx, KNC_SIDE_OUT, dir), buf, len);
}

size_t
knc_get_obufv(knc_ctx ctx, int dir, struct iovec **vec, int *count)
{

	if (!ctx)
		return 0;

	return knc_get_ostreamv(knc_find_buf(ctx,KNC_SIDE_OUT,dir), vec, count);
}

size_t
knc_drain_buf(knc_ctx ctx, int dir, size_t len)
{

	if (!ctx)
		return 0;

	return knc_stream_drain(knc_find_buf(ctx, KNC_SIDE_OUT, dir), len);
}

size_t
knc_fill_buf(knc_ctx ctx, int dir, size_t len)
{

	if (!ctx)
		return 0;

	return knc_stream_fill(knc_find_buf(ctx, KNC_SIDE_IN, dir), len);
}

size_t
knc_pending(knc_ctx ctx, int dir)
{
	size_t	ret;

	if (!ctx)
		return 0;

//	if (ctx->state != STATE_SESSION)
//		return 0;

	ret  = knc_stream_avail(knc_find_buf(ctx, KNC_SIDE_OUT, dir));
	ret += knc_stream_avail(knc_find_buf(ctx, KNC_SIDE_IN,  dir));

	return ret;
}

void
knc_initiate(knc_ctx ctx)
{
	char		 tmp[] = "";

	if (!ctx)
		return;

	/* XXXrcd: sanity! */

#if 0	/* XXXrcd: this should go somewhere... */
	/* XXXnico: this doesn't belong at all; it might not be krb5 */
	KNCDEBUG(ctx, ("going to get tickets for: %s", (char *)name.value));
#endif

	ctx->gssctx = GSS_C_NO_CONTEXT;
	ctx->state  = STATE_INIT;

	/*
	 * XXXrcd: Do we have to run init here?  Probably, we do...
	 *         we could run init later in knc_fill/knc_flush?
	 */
	knc_state_init(ctx, tmp, 0);
}

#ifdef SOCK_NONBLOCK
#define	I_SOCK_NONBLOCK	SOCK_NONBLOCK
#else
#define	I_SOCK_NONBLOCK	0
#endif

#ifdef SOCK_CLOEXEC
#define	I_SOCK_CLOEXEC	SOCK_CLOEXEC
#else
#define	I_SOCK_CLOEXEC	0
#endif

#ifdef SOCK_NOSIGPIPE
#define	I_SOCK_NOSIGPIPE	SOCK_NOSIGPIPE
#else
#define	I_SOCK_NOSIGPIPE	0
#endif

static int
socket_options(int s, int opts)
{
	int	flags;

	flags = fcntl(s, F_GETFL, 0);

	flags &= ~(O_NONBLOCK|O_CLOEXEC);

	if (opts & KNC_SOCK_NONBLOCK)
		flags |= O_NONBLOCK;
	if (opts & KNC_SOCK_CLOEXEC)
		flags |= O_CLOEXEC;

#ifdef O_NOSIGPIPE
	flags |= O_NOSIGPIPE;
#endif

	return fcntl(s, F_SETFL, flags);
}

static int
get_socket(int d, int t, int p, int opts)
{
	int	s;

	if (opts & KNC_SOCK_NONBLOCK)
		t |= I_SOCK_NONBLOCK;
	if (opts & KNC_SOCK_CLOEXEC)
		t |= I_SOCK_CLOEXEC;

	t |= I_SOCK_NOSIGPIPE;

	s = socket(d, t, p);

#if !(I_SOCK_NONBLOCK || I_SOCK_CLOEXEC || I_SOCK_NOSIGPIPE)
	socket_options(s, opts);
#endif

	return s;
}

static int
connect_host(knc_ctx ctx, const char *domain, const char *service, int flags)
{
	struct	addrinfo ai, *res, *res0;
	int	ret;
	int	s = -1;

	KNCDEBUG(ctx, ("connecting to (%s, %s)", service, domain));

	memset(&ai, 0x0, sizeof(ai));
	ai.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(domain, service, &ai, &res0);
	if (ret) {
		KNCDEBUG(ctx, ("getaddrinfo: (%s,%s) %s", domain, service,
		    gai_strerror(ret)));
		return -1;
	}

	for (res=res0; res; res=res->ai_next) {
		s = get_socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol, flags);
		if (s == -1) {
			KNCDEBUG(ctx, ("connect: %s", strerror(errno)));
			continue;
		}
		ret = connect(s, res->ai_addr, res->ai_addrlen);
		if (ret != -1)
			break;
		close(s);
		s = -1;
		KNCDEBUG(ctx, ("connect: %s", strerror(errno)));
	}

	freeaddrinfo(res0);
	return s;
}

/* The Easy Interfaces */

void
knc_garbage_collect(knc_ctx ctx)
{

	if (!ctx)
		return;

	knc_stream_garbage_collect(&ctx->raw_recv);
	knc_stream_garbage_collect(&ctx->raw_send);
	knc_stream_garbage_collect(&ctx->cooked_recv);
	knc_stream_garbage_collect(&ctx->cooked_send);
}

static ssize_t
fdread(void *cookie, void *buf, size_t len)
{
	int	fd = ((struct fd_cookie *)cookie)->rfd;

	return read(fd, buf, len);
}

static ssize_t
fdwritev(void *cookie, const struct iovec *iov, int iovcnt)
{
	int	fd = ((struct fd_cookie *)cookie)->wfd;

	return writev(fd, iov, iovcnt);
}

static int
fdclose(void *cookie)
{
	struct fd_cookie	*fdc = cookie;
	int			 rfd = fdc->rfd;
	int			 wfd = fdc->wfd;

	if (!fdc->mine)
		return 0;

	if (rfd != wfd)
		close(wfd);

	return close(rfd);
}

void
knc_set_net_fds(knc_ctx ctx, int rfd, int wfd)
{
	struct fd_cookie	*cookie;

	if (!ctx)
		return;

	/* XXXrcd: should we look for existing read/writev/close? */

	cookie = malloc(sizeof(*cookie));
	if (!cookie) {
		knc_enomem(ctx);
		return;
	}

	cookie->mine = 0;
	cookie->rfd  = rfd;
	cookie->wfd  = wfd;

	ctx->net_uses_fd = 1;
	ctx->net_is_open = 1;

	ctx->netcookie = cookie;
	ctx->netread   = fdread;
	ctx->netwritev = fdwritev;
	ctx->netclose  = fdclose;
}

void
knc_set_net_fd(knc_ctx ctx, int fd)
{

	knc_set_net_fds(ctx, fd, fd);
}

int
knc_get_net_rfd(knc_ctx ctx)
{

	if (ctx && ctx->net_uses_fd)
		return ((struct fd_cookie *)ctx->netcookie)->rfd;

	return -1;
}

int
knc_get_net_wfd(knc_ctx ctx)
{

	if (ctx && ctx->net_uses_fd)
		return ((struct fd_cookie *)ctx->netcookie)->wfd;

	return -1;
}

int
knc_net_is_open(knc_ctx ctx)
{

	return ctx && ctx->net_uses_fd && ctx->net_is_open;
}

void
knc_set_local_fds(knc_ctx ctx, int rfd, int wfd)
{
	struct fd_cookie	*cookie;

	if (!ctx)
		return;

	/* XXXrcd: should we look for existing read/writev/close? */

	cookie = malloc(sizeof(*cookie));
	if (!cookie) {
		knc_enomem(ctx);
		return;
	}

	cookie->mine = 0;
	cookie->rfd  = rfd;
	cookie->wfd  = wfd;

	ctx->local_uses_fd = 1;
	ctx->local_is_open = 1;

	ctx->localcookie = cookie;
	ctx->localread   = fdread;
	ctx->localwritev = fdwritev;
	ctx->localclose  = fdclose;
}

void
knc_set_local_fd(knc_ctx ctx, int fd)
{

	knc_set_local_fds(ctx, fd, fd);
}

int
knc_get_local_rfd(knc_ctx ctx)
{

	if (ctx && ctx->local_uses_fd)
		return ((struct fd_cookie *)ctx->localcookie)->rfd;

	return -1;
}

int
knc_get_local_wfd(knc_ctx ctx)
{

	if (ctx && ctx->local_uses_fd)
		return ((struct fd_cookie *)ctx->localcookie)->wfd;

	return -1;
}

int
knc_local_is_open(knc_ctx ctx)
{

	return ctx && ctx->local_uses_fd && ctx->local_is_open;
}

int
knc_need_input(knc_ctx ctx, int dir)
{

	if (!ctx)
		return 0;

	/*
	 * We only check the amount of data we have decrypted, because
	 * we could lockup if we don't try to read when we have a
	 * partial packet in the ctx->raw_recv buffer.
	 */

	if (dir == KNC_DIR_RECV)
		return knc_stream_avail(&ctx->cooked_recv) < ctx->recvinbufsiz;

	return knc_pending(ctx, KNC_DIR_SEND) < ctx->sendinbufsiz;
}

int
knc_can_output(knc_ctx ctx, int dir)
{

	if (!ctx)
		return 0;

	return knc_pending(ctx, dir) > 0;
}

static void _fill_recv(knc_ctx ctx)  { knc_fill(ctx, KNC_DIR_RECV); }
static void _fill_send(knc_ctx ctx)  { knc_fill(ctx, KNC_DIR_SEND); }
static void _flush_send(knc_ctx ctx) { knc_flush(ctx, KNC_DIR_SEND, 0); }
static void _flush_recv(knc_ctx ctx) { knc_flush(ctx, KNC_DIR_RECV, 0); }

/* XXXrcd: arg, -1 ain't no nfds_t but we need to return errors... */
/*
 * XXXnico: that's OK, (nfds_t)-1 works, if the caller knows to check
 *	    for that.
 */

nfds_t
knc_get_pollfds(knc_ctx ctx, struct pollfd *fds, knc_callback *cbs,
		nfds_t nfds)
{
	nfds_t	i = 0;

	if (!ctx)
		return 0;

	if (ctx->net_uses_fd && ctx->net_is_open) {
		if (knc_need_input(ctx, KNC_DIR_RECV)) {
			cbs[i]		= _fill_recv;
			fds[i].fd	= knc_get_net_rfd(ctx);
			fds[i++].events	= POLLIN;
			if (i >= nfds)
				return (nfds_t)-1;
		}

		if (knc_can_output(ctx, KNC_DIR_SEND)) {
			cbs[i]		= _flush_send;
			fds[i].fd	= knc_get_net_wfd(ctx);
			fds[i++].events = POLLOUT;
			if (i >= nfds)
				return (nfds_t)-1;
		}
	}

	if (ctx->local_uses_fd && ctx->local_is_open) {
		/*
		 * Here, we are reading unframed bytes and so we size our
		 * buffer as the slightly more accurate raw+cooked size for
		 * comparison.
		 */
		if (knc_need_input(ctx, KNC_DIR_SEND)) {
			cbs[i]		= _fill_send;
			fds[i].fd	 = knc_get_local_rfd(ctx);
			fds[i++].events	 = POLLIN;
			if (i >= nfds)
				return (nfds_t)-1;
		}

		if (knc_can_output(ctx, KNC_DIR_RECV) > 0) {
			cbs[i]		= _flush_recv;
			fds[i].fd	 = knc_get_local_wfd(ctx);
			fds[i++].events	 = POLLOUT;
		}
	}

	return i;
}

void
knc_service_pollfds(knc_ctx ctx, struct pollfd *fds, knc_callback *cbs,
		    nfds_t nfds)
{
	size_t	i;

	if (!ctx)
		return;

	for (i=0; i < nfds; i++) {
		short	revents = fds[i].revents;

		if (revents & (POLLIN|POLLOUT))
			cbs[i](ctx);

	}
}

/*
 * The full requirement here is service@host:port.  The defaults are
 * passed in as parameters to knc_connect.
 */

knc_ctx
knc_connect(knc_ctx ctx, const char *hostservice,
	    const char *defservice, const char *defport,
	    int opts)
{
	char		*buf;
	char		*tmp;
	const char	*service;
	const char	*host;
	const char	*port;
	int		 fd;

	if (!ctx)
		ctx = knc_ctx_init();

	if (!ctx)
		return NULL;

	buf = strdup(hostservice);
	if (!buf) {
		knc_enomem(ctx);
		return ctx;
	}

	tmp = strchr(buf, '@');
	if (tmp) {
		service = buf;
		*tmp++ = '\0';
		host = tmp;
	} else {
		service = defservice;
		host = buf;
	}

	tmp = strchr(host, ':');
	if (tmp) {
		*tmp++ = '\0';
		port = tmp;
	} else {
		port = defport;
	}

	if (!port)
		port = service;

	/* XXXrcd: Hell's Bells, the above needs to be fixed. */

	knc_import_set_hb_service(ctx, host, service);

	fd = connect_host(ctx, host, port, opts);
	if (fd == -1) {
		knc_syscall_error(ctx, "connect_host", errno);
		goto out;
	}

	knc_set_net_fd(ctx, fd);
	((struct fd_cookie *)ctx->netcookie)->mine = 1;
	knc_initiate(ctx);

out:
	free(buf);
	return ctx;
}

static int
errno_switch(knc_ctx ctx, int e, int *is_open, const char *errstr)
{

	switch (e) {
#if EAGAIN != EWOULDBLOCK
	case EWOULDBLOCK:
#endif
	case EINTR:
	case EAGAIN:
		break;

	default:
		/* XXXrcd: hmmm! more than this, I think. */
		*is_open = 0;
		knc_syscall_error(ctx, errstr, e);
	}

	knc_garbage_collect(ctx);
	return errno;
}

int
knc_fill(knc_ctx ctx, int dir)
{
	ssize_t	  len;
	void	 *tmpbuf;
	ssize_t	(*ourread)(void *, void *, size_t);
	void	 *ourcookie;
	int	 *is_open;
	ssize_t	  ret;

	if (!ctx || ctx->error)
		return EIO;

	if (dir == KNC_DIR_SEND) {
		ourread   =  ctx->localread;
		ourcookie =  ctx->localcookie;
		is_open   = &ctx->local_is_open;
	} else {
		ourread   = ctx->netread;
		ourcookie = ctx->netcookie;
		is_open   = &ctx->net_is_open;
	}

	/* XXXrcd: deal properly with EOF */
	/* XXXrcd: looping? */
	/* XXXrcd: hmmm! */

	if (!ourread || !ourcookie)
		return EINVAL;

	/* XXXrcd: hardcoded constant */
	len = knc_get_ibuf(ctx, dir, &tmpbuf, 16 * 1024);
	if (!len) {
		knc_enomem(ctx);
		return ENOMEM;
	}

	KNCDEBUG(ctx, ("knc_fill: about to read %zd bytes.\n", len));

	ret = ourread(ourcookie, tmpbuf, (size_t)len);

	if (ret == -1) {
		KNCDEBUG(ctx, ("read error: %s\n", strerror(errno)));
		return errno_switch(ctx, errno, is_open, "reading");
	}

	if (ret == 0) {
		KNCDEBUG(ctx, ("knc_fill: got EOF\n"));
		/*
		 * XXXrcd: we may very well call this an error because
		 *         we are supposed to see an appropriate command
		 *         packet for close.
		 */
		*is_open = 0;
		knc_generic_error(ctx, "Short input");
		knc_garbage_collect(ctx);
		return EIO;
	}

	if (ret > 0) {
		KNCDEBUG(ctx, ("Read %zd bytes\n", ret));
		knc_fill_buf(ctx, dir, (size_t)ret); /* XXXnice: errors? */
	}

	if (dir == KNC_DIR_RECV)
		knc_state_process_in(ctx);

	knc_garbage_collect(ctx);

	return 0;
}

int
knc_flush(knc_ctx ctx, int dir, size_t flushlen)
{
	struct iovec	*vec;
	int		 iovcnt;
	size_t		 completelen = 0;
	ssize_t		 len;
	ssize_t		(*ourwritev)(void *, const struct iovec *, int);
	void		 *ourcookie;
	int		 *is_open;

	if (!ctx || ctx->error)
		return EIO;

	if (dir == KNC_DIR_SEND) {
		ourwritev =  ctx->netwritev;
		ourcookie =  ctx->netcookie;
		is_open   = &ctx->net_is_open;
	} else {
		ourwritev =  ctx->localwritev;
		ourcookie =  ctx->localcookie;
		is_open   = &ctx->local_is_open;
	}

	for (;;) {
		if (dir == KNC_DIR_SEND)
			knc_state_process_out(ctx);

		len = knc_get_obufv(ctx, dir, &vec, &iovcnt);
		if (len <= 0)
			break;
		KNCDEBUG(ctx, ("knc_flush: about to write %zu bytes.\n", len));

		len = ourwritev(ourcookie, vec, iovcnt);

		if (len == -1) {
			KNCDEBUG(ctx, ("write error: %s\n", strerror(errno)));
			return errno_switch(ctx, errno, is_open, "writev");
		}

		KNCDEBUG(ctx, ("knc_flush: wrote %zd bytes.\n", len));
		knc_drain_buf(ctx, dir, (size_t)len);

		knc_garbage_collect(ctx);

		completelen += len;
		if (completelen >= flushlen)
			break;
	}

	return 0;
}

void
knc_authenticate(knc_ctx ctx)
{
	knc_callback	cbs[4];
	struct pollfd	fds[4];
	nfds_t		nfds;
	int		ret;

	if (!ctx)
		return;

	while (!knc_is_authenticated(ctx) && !knc_error(ctx)) {
		nfds = knc_get_pollfds(ctx, fds, cbs, 4);
		ret = poll(fds, nfds, -1);
		if (ret == -1) {
			knc_syscall_error(ctx, "poll", errno);
			break;
		}
		knc_service_pollfds(ctx, fds, cbs, nfds);
		knc_garbage_collect(ctx);
	}
}

static size_t
reads_get_buf(knc_ctx ctx, void *buf, size_t len)
{
	size_t	 ret;
	size_t	 total;
	void	*tmp;

	total = 0;
	for (;;) {
		ret = knc_get_obuf(ctx, KNC_DIR_RECV, &tmp, len - total);

		if (ret == 0)
			break;

		memcpy((char *)buf + total, tmp, ret);
		knc_drain_buf(ctx, KNC_DIR_RECV, ret);
		total += ret;

		if (total == len)
			break;
	}

	return total;
}

static ssize_t
internal_read(knc_ctx ctx, void *buf, size_t len, int full)
{
	ssize_t	 ret;
	ssize_t	 total;
	int	 fillerr;

	KNCDEBUG(ctx, ("knc_read: about to read.\n"));

	if (!ctx) {
		errno = EBADF;
		return -1;
	}

	/*
	 * We attempt to return data before we initiate a
	 * read because the read may block and we shouldn't
	 * block if there is data available to return.
	 */

	total = reads_get_buf(ctx, buf, len);

	if ((!full && total > 0) || total == (ssize_t)len)
		return total;

	/*
	 * If the socket is non-blocking: flush output before reading.
	 * The goal here is to make standard request response protocols
	 * used in blocking mode more likely to work.  We only perform
	 * the flush before we attempt an actual read which is why this
	 * code is below that which comes above.
	 */
	if (!(ctx->opts & KNC_SOCK_NONBLOCK))
		knc_flush(ctx, KNC_DIR_SEND, -1);

	for (;;) {
		fillerr = knc_fill(ctx, KNC_DIR_RECV);

		switch (fillerr) {
		case 0:
			/* mmm, no error, let's go. */
			break;

#if EAGAIN != EWOULDBLOCK
		case EWOULDBLOCK:
#endif
		case EAGAIN:
			if (ctx->opts & KNC_SOCK_NONBLOCK) {
				errno = fillerr;
				return -1;
			}
			/*
			 * XXXrcd: really this should be an error if we
			 *         are in blocking mode as why would we
			 *         get this unless someone has naughtily
			 *         lied to us?  At least, if this is going
			 *         to occur, we should poll(2).
			 */
			break;

		default:
			errno = fillerr;
			return -1;
		}

		if (!ctx->net_is_open)
			/* XXXrcd: double check this idea... */
			return 0;

		ret = reads_get_buf(ctx, (char *)buf + total, len - total);
		total += ret;
		if ((!full && total > 0) || total == (ssize_t)len)
			break;
	}

	return total;
}

ssize_t
knc_read(knc_ctx ctx, void *buf, size_t len)
{

	return internal_read(ctx, buf, len, 0);
}

ssize_t
knc_fullread(knc_ctx ctx, void *buf, size_t len)
{

	return internal_read(ctx, buf, len, 1);
}

ssize_t
knc_write(knc_ctx ctx, const void *buf, size_t len)
{
	ssize_t	ret;

	if (!ctx) {
		errno = EBADF;
		return -1;
	}

	if (ctx->error) {
		errno = EIO;
		return -1;
	}

	if (!ctx->net_is_open) {
		errno = EPIPE;
		return -1;
	}

	ret = knc_put_buf(ctx, KNC_DIR_SEND, buf, len);

	/* XXXrcd: I'm abusing sendinbufsiz here, this isn't good. */
	if (knc_pending(ctx, KNC_DIR_SEND) > ctx->sendinbufsiz)
		knc_flush(ctx, KNC_DIR_SEND, 0);

	if (knc_error(ctx)) {
		errno = ctx->errnum ? ctx->errnum : EIO; /* XXXnico: ... */
		return 0;
	}

	return ret;
}


/* XXXrcd: review this code against gssstdio.c! */

static char *
knc_errstring(OM_uint32 maj_stat, OM_uint32 min_stat, const char *preamble)
{
	gss_buffer_desc	 status;
	OM_uint32	 new_stat;
	OM_uint32	 cur_stat;
	OM_uint32	 msg_ctx = 0;
	OM_uint32	 ret;
	int		 type;
	size_t		 newlen;
	char		*str = NULL;
	char		*tmp = NULL;

	cur_stat = maj_stat;
	type = GSS_C_GSS_CODE;

	for (;;) {

		/*
		 * GSS_S_FAILURE produces a rather unhelpful message, so
		 * we skip straight to the mech specific error in this case.
		 */

		if (type == GSS_C_GSS_CODE && cur_stat == GSS_S_FAILURE) {
			type = GSS_C_MECH_CODE;
			cur_stat = min_stat;
		}

		ret = gss_display_status(&new_stat, cur_stat, type,
		    GSS_C_NO_OID, &msg_ctx, &status);

		if (GSS_ERROR(ret))
			return str;	/* XXXrcd: hmmm, not quite?? */

		if (str)
			newlen = strlen(str);
		else
			newlen = strlen(preamble);

		newlen += status.length + 3;

		tmp = str;
		str = malloc(newlen);

		if (!str) {
			gss_release_buffer(&new_stat, &status);
			return tmp;	/* XXXrcd: hmmm, not quite?? */
		}

		snprintf(str, newlen, "%s%s%.*s", tmp?tmp:preamble,
		    tmp?", ":": ", (int)status.length, (char *)status.value);

		gss_release_buffer(&new_stat, &status);
		free(tmp);

		/*
		 * If we are finished processing for maj_stat, then
		 * move onto min_stat.
		 */

		if (msg_ctx == 0 && type == GSS_C_GSS_CODE && min_stat != 0) {
			type = GSS_C_MECH_CODE;
			cur_stat = min_stat;
			continue;
		}

		if (msg_ctx == 0)
			break;
	}

	return str;
}

static void
knc_generic_error(knc_ctx ctx, const char *str)
{

	/* XXXrcd: wrong type */
	ctx->error  = KNC_ERROR_GENERIC;
	ctx->errstr = strdup(str);
}

static void
knc_syscall_error(knc_ctx ctx, const char *str, int number)
{
	char	*errstr;
	char	*tmp;

	ctx->error = KNC_ERROR_GENERIC;

	errstr = strerror(number);
	tmp = malloc(strlen(str) + strlen(errstr) + 3);

	if (tmp)
		sprintf(tmp, "%s: %s", str, errstr);

	ctx->errstr = tmp;
}

static void
knc_nomem(knc_ctx ctx)
{
    knc_syscall_error(ctx, "Out of memory", ENOMEM);
}

static int
knc_stream_error(knc_ctx ctx, struct knc_stream *s)
{
	if (!s->errnum)
		return 0;
	knc_syscall_error(ctx, s->failed_func, s->errnum);
	return ctx->error;
}

static void
knc_gss_error(knc_ctx ctx, OM_uint32 maj_stat, OM_uint32 min_stat,
	      const char *s)
{

	ctx->error = KNC_ERROR_GSS;
	ctx->errstr = knc_errstring(maj_stat, min_stat, s);
	if (!ctx->errstr)
		ctx->errstr = strdup("Failed to construct GSS error");
	KNCDEBUG(ctx, ("knc_gss_error: %s\n", ctx->errstr));
}

static void
knc_enomem(knc_ctx ctx)
{

	knc_syscall_error(ctx, "Out of memory", ENOMEM);
}
