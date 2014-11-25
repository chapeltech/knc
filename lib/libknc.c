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

#ifdef	HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#define	__USE_GNU
#include <fcntl.h>
#undef	__USE_GNU
#include <malloc.h>
#include <netdb.h>
#include <signal.h>
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
#include "private.h"

#define oom_gss_msg "No memory while constructing GSS error message"
#define gen_gss_msg "Failed to construct GSS error"
#define bad_gss_msg "GSS doesn't recognize its own errors!"

struct stream_bit {
	int			  type;
#define	STREAM_BUFFER	0x1
#define STREAM_COMMAND	0x2
/* XXXrcd: we may want to push errors onto the streams, too? */
	void			 *buf;
	void			(*free)(void *, void *);
	void			 *cookie;
	struct stream_bit	 *next;
	size_t			  len;
	size_t			  allocated;
};

struct stream_gc {
	void			*ptr;
	struct stream_gc	*next;
};

struct stream {
	struct stream_bit	*head;
	struct stream_bit	*cur;
	struct stream_bit	*tail;
	struct stream_gc	*garbage;
	int			 collecting;	/* g/c is ongoing */
	size_t			 bufpos;
	size_t			 avail;
};

typedef struct stream_bit *stream_bit;
typedef struct stream_gc *stream_gc;
typedef struct stream *stream;

struct internal_knc_ctx {
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
	size_t			 sent_tot;
	size_t			 recv_tot;

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
	int			 debug;
	char			 debug_prefix[64];
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

	int			 unwrapped_one; /* for async errors */

	struct stream		 raw_recv;
	struct stream		 cooked_recv;
	struct stream		 raw_send;
	struct stream		 cooked_send;

	/*
	 * These are the read/write/close functions, they will be executed
	 * at the correct time by the code if they are defined.  If they
	 * are not defined, they will not be executed.
	 */

	int	  net_uses_fd;
	void	 *netcookie;
	ssize_t	(*netread)(void *, void *, size_t);
	ssize_t	(*netwritev)(void *, const struct iovec *, int);
	int	(*netclose)(void *);

	int	  local_uses_fd;
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

#define MAX_IOVCNT	32

#define KNC_GSS_ERROR(_ctx, _maj, _min, _ret, _str) do {		\
		if (GSS_ERROR((_maj))) {				\
			knc_gss_error((_ctx), (_maj), (_min), (_str));	\
			return _ret;					\
		}							\
	} while (0/*CONSTCOND*/)

#define MIN(a, b)	((a)<(b)?(a):(b))

#ifdef LOW_LEVEL_DEBUGGERY
/* XXXrcd: eventually get rid of DEBUG() */
int debug = 0;
#define DEBUG(x) do {				\
		if (debug) {			\
			debug_printf x ;	\
		}				\
	} while (0/*CONSTCOND*/)
#else
#define DEBUG(x)
#endif

#define KNCDEBUG(x) do {		\
		debug_printf x ;	\
	} while (0/*CONSTCOND*/)

/* Local function declarations */

static void	debug_printf(knc_ctx, const char *, ...)
    __attribute__((__format__(__printf__, 2, 3)));

static void		destroy_stream(stream);
static stream_bit	alloc_stream_bit(int, size_t);
static size_t		append_stream_bit(stream, stream_bit);

static size_t	put_stream(stream, const void *, size_t);
static size_t	put_stream_userbuf(stream, void *, size_t,
		    void (*)(void *, void *), void *);
static size_t	put_stream_gssbuf(stream, gss_buffer_t);
static size_t	get_istream(stream, void **, size_t);
static size_t	get_ostream(stream, void **, size_t);
static size_t	get_ostreamv(stream, int, struct iovec **, int *);
static int	stream_put_trash(stream, void *);
static size_t	get_ostream_contig(stream, void **, size_t);
static ssize_t	stream_drain(stream, size_t);
static ssize_t	stream_fill(stream, size_t);
static size_t	stream_avail(stream);
static void	stream_garbage_collect(stream);

static int	socket_options(int, int);
static size_t	read_packet(stream, void **b);
static size_t	put_packet(knc_ctx, gss_buffer_t);
static size_t	wrap_and_put_packet(knc_ctx, char *, size_t);

static int	knc_state_init(knc_ctx, void *, size_t);
static int	knc_state_accept(knc_ctx, void *, size_t);
static int	knc_state_session(knc_ctx, void *, size_t);
static int	knc_state_command(knc_ctx, void *, size_t);
static int	knc_state_process_in(knc_ctx);
static int	knc_state_process_out(knc_ctx);

static stream	knc_find_buf(knc_ctx, int, int);

/* And, ta da: the code */

static void
debug_printf(knc_ctx ctx, const char *fmt, ...)
{
	va_list ap;

	if (ctx && !ctx->debug)
		return;

#ifdef LOW_LEVEL_DEBUGGERY
	if (!ctx && !debug)
		return;
#endif

	if (ctx && *ctx->debug_prefix)
		fprintf(stderr, "%s: ", ctx->debug_prefix);
	else
		fprintf(stderr, "%d: ", getpid());
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void
destroy_stream(stream s)
{

	if (!s)
		return;

	s->cur = NULL;
	stream_garbage_collect(s);
}

static size_t
append_stream_bit(stream s, stream_bit b)
{

	assert( (!s->head && !s->tail) || (s->head && s->tail) );

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

static stream_bit
alloc_stream_bit(int type, size_t len)
{
	stream_bit	 bit;
	char		*tmpbuf;

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

	bit->type	= type;
	bit->buf	= tmpbuf;
	bit->len	= 0;
	bit->allocated	= len;

	return bit;
}

static size_t
put_stream(stream s, const void *buf, size_t len)
{
	void	*newbuf;
	size_t	 ret;
	size_t	 total = 0;

	while (len > 0) {
		ret = get_istream(s, &newbuf, len);

		if (!ret)
			/* malloc failed: stop */
			break;

		memcpy(newbuf, buf, ret);
		stream_fill(s, ret);

		len   -= ret;
		total += ret;
	}

	return total;
}

static size_t
put_stream_userbuf(stream s, void *buf, size_t len,
		   void (*callback)(void *, void *), void *cookie)
{
	stream_bit	bit;

	bit = calloc(1, sizeof(*bit));
	if (!bit)
		/* XXXrcd: hmmm, maybe we should raise an error here? */
		return 0;

	bit->type	= STREAM_BUFFER;
	bit->buf	= buf;
	bit->allocated	= len;
	bit->len	= len;
	bit->free	= callback;
	bit->cookie	= cookie;

	return append_stream_bit(s, bit);
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
put_stream_gssbuf(stream s, gss_buffer_t inbuf)
{
	gss_buffer_t	buf;

	buf = calloc(1, sizeof(*buf));
	if (!buf)
		/* XXXrcd: raise an error here? */
		return 0;

	buf->value  = inbuf->value;
	buf->length = inbuf->length;

	return put_stream_userbuf(s, buf->value, buf->length, free_gssbuf,
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

/*
 * XXXrcd: this really can't be an exported interface in the future,
 *         we think as mmap(2) is not implemented with sanity on Linux.
 *         We will need to come up with a new interface for this.
 */

static ssize_t
put_stream_mmapbuf(struct stream *s, size_t len, int flags, int fd,
		       off_t offset)
{
	struct mmapregion	*r;
	off_t			 add_offset;

	r = calloc(1, sizeof(*r));
	if (!r)
		return -1;

	add_offset = offset % sysconf(_SC_PAGESIZE);
	offset -= add_offset;

	r->buf = mmap(NULL, len + add_offset, PROT_READ, flags, fd, offset);
	r->len = len;

	/* XXXrcd: better errors would be appreciated... */

	if (r->buf == MAP_FAILED) {
		/* XXXrcd: leave current errno */
		free(r);
		return -1;
	}

	return put_stream_userbuf(s, (char *)r->buf + add_offset, r->len,
	    free_mmapbuf, r);
}

static size_t
put_stream_command(stream s, void *buf, size_t len)
{
	stream_bit	tmp;

	/* Must mark current one as being full, innit? */

	if (s->tail)
		s->tail->allocated = s->tail->len;

	/*
	 * XXXrcd: might be an idea to use a new alloc which doesn't
	 *         try to make a buffer that we can grow into per se.
	 */
	tmp = alloc_stream_bit(STREAM_COMMAND, len);
	if (!tmp)
		return 0;

	memcpy(tmp->buf, buf, len);
	tmp->len = len;
	tmp->allocated = len;

	append_stream_bit(s, tmp);

	return len;
}

static int
knc_get_stream_bit_type(stream s)
{

	if (!s || !s->cur)
		return 0;

	return s->cur->type;
}

static void *
knc_get_stream_command(stream s, size_t *len)
{
	void	*ret;

	if (!s || !s->cur)
		return NULL;

	*len = s->cur->len;
	 ret = s->cur->buf;

	s->cur = s->cur->next;

	s->avail -= *len;

	return ret;
}

static size_t
get_istream(stream s, void **buf, size_t len)
{
	stream_bit	tmp;
	size_t		remaining;

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

	tmp = alloc_stream_bit(STREAM_BUFFER, len);
	if (!tmp)
		return 0;

	append_stream_bit(s, tmp);

	*buf = tmp->buf;
	return MIN(len, tmp->allocated);
}

/*
 * get_ostream specifically only returns a single stream_bit.
 * get_ostream returns a ptr into its data structure, the caller
 * may not modify it.  This allows the caller to construct an iovec
 * for writing.
 */

static size_t
get_ostream(stream s, void **buf, size_t len)
{

	if (!s || !s->cur)
		/* Nothing here... */
		return 0;

	DEBUG((NULL, "get_ostream: s->cur = %p\n", s->cur));

	/* XXXrcd: hmmm, what if bufpos moves us beyond the stream? */

	/*
	 * XXXrcd: error if the stream bit is a command?  Shouldn't happen,
	 *         though because the user is not exposed to such streams
	 *         and the internal code doesn't use this func.
	 */

	if (s->cur->len >= s->bufpos) {
		*buf = (char *)s->cur->buf + s->bufpos;
		return MIN(len, s->cur->len - s->bufpos);
	}

	return 0;
}

static size_t
get_ostreamv(stream s, int maxcnt, struct iovec **vec,
	     int *count)
{
	stream_bit	cur;
	int		i;
	size_t		len;

	if (!s || !s->cur)
		/* Nothing here */
		return 0;

	/*
	 * XXXrcd: error if the stream bit is a command?  Shouldn't happen,
	 *         though because the user is not exposed to such streams
	 *         and the internal code doesn't use this func.
	 */

	/* First we count the bits. */

	i = 0;
	for (cur = s->cur; cur; cur = cur->next)
		/* XXXrcd: test length and all of that? */
		if (i++ == maxcnt)
			break;

	*vec = malloc(i * sizeof(**vec));
	if (!*vec) {
		/* XXXrcd: better errors... */
		return 0;
	}

	i = 0;
	len = 0;
	cur = s->cur;

	(*vec)[i  ].iov_base = (char *)cur->buf + s->bufpos;
	(*vec)[i++].iov_len  = cur->len - s->bufpos;
	len += cur->len - s->bufpos;
	DEBUG((NULL, "creating iovec element of length %zu, total %zu\n",
	    len, len));

	for (cur = cur->next; cur; cur = cur->next) {
		(*vec)[i].iov_base = cur->buf;
		(*vec)[i].iov_len  = cur->len;
		len += cur->len;
		DEBUG((NULL, "creating iovec element of length %zu, "
		    "total %zu\n", cur->len, len));
		if (i++ == maxcnt)
			break;
	}

	*count = i;
	stream_put_trash(s, *vec);

	return len;
}

/*
 * get_ostream_contig() will fetch an entire contiguous newly allocated
 * buffer of the desired length, if it exists.  This may involve copying, but
 * it may not.  The caller is still not allowed to either modify or free(3)
 * the returned buffer.
 */

static size_t
get_ostream_contig(stream s, void **buf, size_t len)
{
	stream_bit	cur;
	size_t		retlen;
	size_t		tmplen;

	if (!s || !s->cur)
		return 0;

	/* We adjust len down to the available bytes */

	tmplen = stream_avail(s);
	len = MIN(tmplen, len);

	/*
	 * Then, let's see if we have a single bit that fills this up.
	 * If we do, we can process this request without copying.
	 */

	tmplen = get_ostream(s, buf, len);
	if (tmplen == len)
		return len;

	/* Okay, we're going to have to allocate here. */

	*buf = malloc(len);
	if (*buf == NULL)
		return 0;
	stream_put_trash(s, *buf);

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

		if (!cur || cur->type != STREAM_BUFFER)
			break;
	}

	return retlen;
}

static ssize_t
stream_drain(stream s, size_t len)
{

	DEBUG((NULL, "stream_drain called with %zu\n", len));

	if (!s->cur)
		return -1;

	/* XXXrcd: sanity */
	DEBUG((NULL, "stream_drain(%zu) start: s->cur=%p, avail=%zu "
	    "bufpos=%zu\n", len, s->cur, s->avail, s->bufpos));

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

	DEBUG((NULL, "stream_drain end: s->cur = %p\n", s->cur));

	return len;
}

static ssize_t
stream_fill(stream s, size_t len)
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
stream_avail(stream s)
{

	return s->avail;
}

static int
stream_put_trash(stream s, void *ptr)
{
	stream_gc	tmp;

	/*
	 * XXXrcd: we should allocate space for the rubbish before
	 *         we allocate it as if we fail this malloc, we will
	 *         start to leak because we aren't free(3)ing the
	 *         garbage.
	 */

	tmp = malloc(sizeof(*tmp));
	if (!tmp)
		/* XXXrcd: ??? */
		return -1;

	tmp->ptr = ptr;
	tmp->next = s->garbage;
	s->garbage = tmp;

	return 0;
}

/*
 * stream_garbage_collect is provided because get_ostream does
 * not actually deallocate the memory that is associated with it.
 * knc_clean_buf() will deallocate all memory between head and cur.
 */

static void
stream_garbage_collect(stream s)
{
	stream_bit	tmpbit;
	stream_gc	gc;
	stream_gc	tmpgc;

	if (!s || s->collecting)
		return;

	/*
	 * s->collecting isn't a mutex because we aren't supposed
	 * to be thread safe.  We are simply making sure that when
	 * we call our callback that it is safe for it to run
	 * knc_garbage_collect().
	 */
	s->collecting = 1;

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
	s->collecting = 0;
}

static size_t
read_packet(stream s, void **buf)
{
	size_t		 len;
	uint32_t	 wirelen;
	void		*tmp;

	DEBUG((NULL, "read_packet: enter\n"));

	if (get_ostream_contig(s, &tmp, 4) < 4)
		return 0;

	wirelen = ntohl(*((uint32_t *)tmp));

	DEBUG((NULL, "read_packet: got wirelen = %u\n", wirelen));
	if (stream_avail(s) < (size_t)wirelen + 4)
		return 0;

	stream_drain(s, 4);

	/* Okay, now we know that we've got an entire packet */

	DEBUG((NULL, "read_packet: getting %u bytes\n", wirelen));
	len = get_ostream_contig(s, buf, wirelen);

	if (len != wirelen)
		abort();	/* XXXrcd: really shouldn't happen. */

	stream_drain(s, len);

	DEBUG((NULL, "read_packet: %zu left in stream\n", s->avail));
	/* XXXrcd: broken, I think. */

	return len;
}

static size_t
put_packet(knc_ctx ctx, gss_buffer_t buf)
{
	uint32_t	netlen;

	netlen = htonl((uint32_t)buf->length);
	put_stream(&ctx->cooked_send, &netlen, 4);
	put_stream_gssbuf(&ctx->cooked_send, buf);

	/* XXXrcd: useful to return this?  What about errors? */
	return 0;
}

static size_t
wrap_and_put_packet(knc_ctx ctx, char *buf, size_t len)
{
	gss_buffer_desc	 in;
	gss_buffer_desc	 out;
	OM_uint32	 maj;
	OM_uint32	 min;
	int		 privacy = (ctx->opts & KNC_OPT_NOPRIVACY)?0:1;

	in.length = len;
	in.value  = buf;
	maj = gss_wrap(&min, ctx->gssctx, privacy, GSS_C_QOP_DEFAULT,
	    &in, NULL, &out);

	KNC_GSS_ERROR(ctx, maj, min, 0, "gss_wrap");

	return put_packet(ctx, &out);
}

knc_ctx
knc_ctx_init(void)
{
	knc_ctx	ret;

	ret = calloc(1, sizeof(*ret));

	/* Set some reasonable defaults */

	ret->gssctx		= GSS_C_NO_CONTEXT;
	ret->client		= GSS_C_NO_NAME;
	ret->service		= GSS_C_NO_NAME;
	ret->imp_service	= GSS_C_NO_NAME;
	ret->inq_service	= GSS_C_NO_NAME;
	ret->cred		= GSS_C_NO_CREDENTIAL;
	ret->cb			= GSS_C_NO_CHANNEL_BINDINGS;
	ret->req_mech		= GSS_C_NO_OID;
	ret->ret_mech		= GSS_C_NO_OID;
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
knc_set_debug_prefix(knc_ctx ctx, const char *setting)
{

	snprintf(ctx->debug_prefix, sizeof(ctx->debug_prefix), "%s", setting);
}

void
knc_ctx_destroy(knc_ctx ctx)
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

	if (ctx->netclose)
		(ctx->netclose)(ctx->netcookie);

	if (ctx->localclose)
		(ctx->localclose)(ctx->localcookie);

	/* XXXrcd: memory leaks?  */
	/* XXXnico: smartass comment: use valgrind */

	if (ctx->errstr != oom_gss_msg && ctx->errstr != gen_gss_msg &&
	    ctx->errstr != bad_gss_msg)
		free(ctx->errstr);

	destroy_stream(&ctx->raw_recv);
	destroy_stream(&ctx->cooked_recv);
	destroy_stream(&ctx->raw_send);
	destroy_stream(&ctx->cooked_send);

	free(ctx);
}

/*
 * Although we renamed this to knc_ctx_destroy(), we leave this
 * for compatibility for the time being...  We do, however, ensure
 * that knc_ctx_close() has no documentation thus reducing its
 * chance of use.
 */

void
knc_ctx_close(knc_ctx ctx)
{

	knc_ctx_destroy(ctx);
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
	case KNC_SOCK_NONBLOCK:
	case KNC_SOCK_CLOEXEC:
		return (ctx->opts & opt) ? 1 : 0;

	case KNC_OPT_SENDINBUFSIZ:
		return (int)ctx->sendinbufsiz;
	case KNC_OPT_RECVINBUFSIZ:
		return (int)ctx->recvinbufsiz;

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
	case KNC_OPT_SENDCMDS:
	case KNC_SOCK_NONBLOCK:
	case KNC_SOCK_CLOEXEC:
		if (value)
			ctx->opts |= opt;
		else
			ctx->opts &= ~opt;
		break;

	case KNC_OPT_SENDINBUFSIZ:
		ctx->sendinbufsiz = value;
		break;

	case KNC_OPT_RECVINBUFSIZ:
		ctx->recvinbufsiz = value;
		break;

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

	/* XXXrcd: sanity?  check if we are an initiator? */
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

	KNCDEBUG((ctx, "knc_state_init: enter\n"));
	ctx->locally_initiated = 1;
	maj = gss_init_sec_context(&min, ctx->cred, &ctx->gssctx,
	    ctx->service, ctx->req_mech, ctx->req_flags, ctx->time_req,
	    ctx->cb, &in, &ctx->ret_mech, &out, &ctx->ret_flags,
	    &ctx->time_rec);

	if (out.length > 0)
		put_packet(ctx, &out);
		/* XXXrcd: errors? */

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

	KNCDEBUG((ctx, "knc_state_accept: enter\n"));

	out.length = 0;

	in.value  = buf;
	in.length = len;

	maj = gss_accept_sec_context(&min, &ctx->gssctx, ctx->cred, &in,
	    ctx->cb, &ctx->client, &ctx->ret_mech, &out,
	    &ctx->ret_flags, &ctx->time_rec, &ctx->deleg_cred);

	if (out.length)
		put_packet(ctx, &out);
		/* XXXrcd: ERRORS?!? */

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
	OM_uint32	maj2;
	OM_uint32	min2;

	in.value  = buf;
	in.length = len;

	out.length = 0;

	KNCDEBUG((ctx, "knc_state_session: enter\n"));
	maj = gss_unwrap(&min, ctx->gssctx, &in, &out, NULL, NULL);

	/* Handle async error context token case */
	if (!ctx->unwrapped_one &&
	    (maj == GSS_S_DEFECTIVE_TOKEN || maj == GSS_S_BAD_SIG)) {
		maj2 = gss_process_context_token(&min2, ctx->gssctx, &in);
		if (maj2 == GSS_S_COMPLETE || maj2 == GSS_S_FAILURE) {
			knc_gss_error(ctx, GSS_S_COMPLETE, min2,
				      "gss_process_context_token");
		}
#ifndef HAVE_GOOD_PROCESS_CONTEXT_TOKEN
		/*
		 * Some implementations of gss_process_context_token()
		 * incorrectly delete the security context when a
		 * context deletion token is used, leading to
		 * double-frees here.  We have no way to detect this at
		 * runtime.  We can't depend on build-time detection of
		 * this either.  Therefore we default to leaking the
		 * context in the worst case instead of dangling
		 * dereference and/or double-free in the worst case.
		 */
		if (maj2 == GSS_S_COMPLETE &&
		    (ctx->opts & KNC_OPT_PROC_CTX_TOK_WORKS) == 0)
			ctx->gssctx = GSS_C_NO_CONTEXT;
#endif
	}

	ctx->unwrapped_one = 1;

	if (maj != GSS_S_COMPLETE) {
		knc_gss_error(ctx, maj, min, "gss_unwrap");
		return -1;
	}

	if (out.length == 0) {
		/* XXXrcd: do we need this release? */
		gss_release_buffer(&min, &out);
		ctx->state = STATE_COMMAND;
		return 0;
	}

	/*
	 * Here, we know that we have data, so we need to decide if we
	 * are in a position to accept it.
	 */

	if (!(ctx->open & OPEN_READ)) {
		knc_generic_error(ctx, "Data after EOF");
		return -1;
	}

	put_stream_gssbuf(&ctx->cooked_recv, &out);

	return 0;
}

/*ARGSUSED*/
static int
cmd_unknown(knc_ctx ctx, uint32_t cmdseqno, void *data, size_t len)
{

	knc_put_command(ctx, "dont_understand", cmdseqno, NULL, 0);
	return 0;
}

/*ARGSUSED*/
static int
cmd_dont_understand(knc_ctx ctx, uint32_t cmdseqno, void *data, size_t len)
{

	return 0;
}

/*ARGSUSED*/
static int
cmd_txt_error(knc_ctx ctx, uint32_t cmdseqno, void *data, size_t len)
{

	/* XXXrcd: this should set error state and kill the connexion */
	return 0;
}

typedef int (*process_command)(knc_ctx, uint32_t, void *, size_t);

struct {
	const char	*cmd;
	process_command	 f;
} string_cmds[] = {
	{ "dont_understand",	cmd_dont_understand},
	{ "txt_error",		cmd_txt_error},
	{ NULL,			NULL},

	/* XXXrcd: send buffer size change requests? */
	/*
	 * XXXrcd: set gss_wrap_buf_siz as well.  Maybe take min of
	 *         both side's proposals.
	 */
	/* XXXrcd: how about TCP buffers... */
	/* XXXrcd: keepalives? should contain data? */
};

static process_command
command_match(knc_ctx ctx, uint32_t *cmdseqno, char **retbuf, uint32_t *retlen)
{
	const char	*value;
	size_t		 len;
	size_t		 i;

	/* retbuf and retlen are inputs and outputs */

	value = *retbuf;
	len   = *retlen;

	/*
	 * The remaining commands shall have a format of:
	 *
	 *	cmdseqno	uint32_t network byte order
	 *	command		nul-terminated string
	 *	datalen		uint32_t netword byte order
	 *	data		dependent on command
	 *
	 * The cmdseqno exists so that it is possible to reply to commands,
	 * if a reply is not necessary then it can be set to zero, otherwise
	 * it should be set to a value not shared with any  other outstanding
	 * command.  XXXrcd: should provide a framework for same when the
	 * time becomes ripe.
	 *
	 * The command shall be in the format of cmd[@dns_domain], where
	 * the organisation defining the command controls the DNS domain
	 * dns_domain and undertakes to keep control of said domain for
	 * the foreseeable future.  A lack of dns_domain is reserved for
	 * the original author.
	 *
	 * We use strings here in this way as we would like to avoid the
	 * issues of allocating numbers centrally.  This scheme is inspired
	 * by the SSH2 protocol.
	 *
	 * We drop malformed commands without reply, XXXrcd: perhaps we
	 * should simply drop the entire connexion?
	 *
	 * Not all commands have replies, e.g. replies.
	 */

	if (len < sizeof(*cmdseqno) + 2 + sizeof(*retlen))
		return NULL;

	memcpy(cmdseqno, value, sizeof(*cmdseqno));
	*cmdseqno = ntohl(*cmdseqno);

	value += sizeof(*cmdseqno);
	len   -= sizeof(*cmdseqno);

	*retbuf = memchr(value, 0x0, len);
	if (!*retbuf)
		return NULL;

	*retbuf += 1;
	len -= ((const char *)*retbuf - (const char *)value);

	if (len < sizeof(*retlen))
		return NULL;

	memcpy(retlen, *retbuf, sizeof(*retlen));
	*retlen = ntohl(*retlen);

	*retbuf += sizeof(*retlen);
	len     -= sizeof(*retlen);

	if (len < *retlen)
		return NULL;

	KNCDEBUG((ctx, "Received command \"%s\", seq=%u, \"%.*s\", len=%u\n",
	    value, *cmdseqno, (int)*retlen, *retbuf, *retlen));

	for (i=0; string_cmds[i].cmd; i++)
		if (!strcmp(value, string_cmds[i].cmd))
			return string_cmds[i].f;

	return cmd_unknown;
}

static int
knc_state_command(knc_ctx ctx, void *buf, size_t len)
{
	gss_buffer_desc	 in;
	gss_buffer_desc	 out;
	OM_uint32	 maj;
	OM_uint32	 min;
	process_command	 cmd;
	uint32_t	 cmdseqno;
	char		*cmdbuf;
	uint32_t	 cmdbuflen;
	size_t		 remainlen;

	in.value  = buf;
	in.length = len;

	out.length = 0;

	KNCDEBUG((ctx, "knc_state_command: enter\n"));
	maj = gss_unwrap(&min, ctx->gssctx, &in, &out, NULL, NULL);

	if (maj != GSS_S_COMPLETE) {
		knc_gss_error(ctx, maj, min, "gss_unwrap");
		return -1;
	}

	/*
	 * We set the state back to STATE_SESSION as no matter what happens
	 * after this, we'll either have processed the command or raised an
	 * error.
	 */

	ctx->state = STATE_SESSION;

	/*
	 * Our EOFs are special short commands which we identify via their
	 * length.  A command of zero length is EOF in both directions.  A
	 * command with a length of one is a read EOF if the byte is 0 and
	 * a write EOF if the byte is 1.
	 */

	if (out.length == 0) {
		KNCDEBUG((ctx, "knc_state_command: received dual EOF\n"));
		/* XXXrcd: should check if we've sent EOF not if we're open */
		if (ctx->open & OPEN_WRITE)
			knc_put_eof(ctx, KNC_DIR_SEND);
		if (ctx->open & OPEN_READ)
			knc_put_eof(ctx, KNC_DIR_RECV);
		ctx->open &= ~(OPEN_READ|OPEN_WRITE);
		goto done;
	}

	if (out.length == 1 && *(char *)out.value == 0) {
		KNCDEBUG((ctx, "knc_state_command: received read EOF\n"));
		ctx->open &= ~OPEN_READ;
		goto done;
	}

	if (out.length == 1 && *(char *)out.value == 1) {
		/* XXXrcd: should check if we've sent EOF not if we're open */
		KNCDEBUG((ctx, "knc_state_command: received write EOF\n"));
		if (ctx->open & OPEN_WRITE)
			knc_put_eof(ctx, KNC_DIR_SEND);
		ctx->open &= ~OPEN_WRITE;
		goto done;
	}

	cmdbuf    = out.value;
	remainlen = out.length;
	do {
		void	*oldptr = cmdbuf;

		cmdbuflen = remainlen;

		cmd = command_match(ctx, &cmdseqno, &cmdbuf, &cmdbuflen);
		if (!cmd) {
			knc_generic_error(ctx, "Malformed command packet");
			goto done;
		}

		cmd(ctx, cmdseqno, cmdbuf, cmdbuflen);

		cmdbuf    += cmdbuflen;
		remainlen -= (const char *)cmdbuf - (const char *)oldptr;
	} while (remainlen > 0);

done:
	gss_release_buffer(&min, &out);
	return 0;
}

static int
knc_state_process_in(knc_ctx ctx)
{
	void	*buf;
	size_t	 len;
	int	 ret;

	KNCDEBUG((ctx, "knc_state_process_in: enter\n"));

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

		KNCDEBUG((ctx, "read_packet returned %zd\n", len));

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

		/* XXXrcd: EOF handling likely wants to go here. */

	}

	/*NOTREACHED*/
	return ret;
}

static int
knc_state_process_out(knc_ctx ctx)
{
	size_t		 len;
	void		*buf;

	KNCDEBUG((ctx, "knc_state_process_out: enter\n"));

	/*
	 * We only process our out buffer if we have established the
	 * GSSAPI connexion because the handshake routines write directly
	 * to ctx->cooked_send.
	 */

	if (ctx->state != STATE_SESSION && ctx->state != STATE_COMMAND)
		return 0;

	while (stream_avail(&ctx->cooked_send) < ctx->sendmax) {
		switch (knc_get_stream_bit_type(&ctx->raw_send)) {
		case STREAM_COMMAND:
			buf = knc_get_stream_command(&ctx->raw_send, &len);
			wrap_and_put_packet(ctx, buf, 0);
			wrap_and_put_packet(ctx, buf, len);
			break;

		case STREAM_BUFFER:
			/*
			 * We clip the length at ctx->gssmaxpacket to make
			 * the job of the receiver easier.
			 */

			len = get_ostream_contig(&ctx->raw_send, &buf,
			    ctx->gssmaxpacket);

			if (len < 1) {
				/* XXXrcd: ERRORS? Maybe there aren't any...? */
				/*
				 * XXXrcd: analyse this one a bit more,
				 * what if we didn't get a byte because there
				 * is a command pending?  Shouldn't happen,
				 * but let's convince ourselves properly at
				 * a later time...
				 */
				return 0;
			}

			wrap_and_put_packet(ctx, buf, len);
			stream_drain(&ctx->raw_send, len);
			break;
		default:
			return 0;
		}

	}

	KNCDEBUG((ctx, "knc_state_process_out: leave\n"));

	return 0;
}

#define KNC_SIDE_IN	0x100
#define KNC_SIDE_OUT	0x200

static stream
knc_find_buf(knc_ctx ctx, int side, int dir)
{
	stream	s;

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

	if (!ctx)
		return 0;

	return put_stream(knc_find_buf(ctx, KNC_SIDE_IN, dir), buf, len);
}

size_t
knc_put_ubuf(knc_ctx ctx, int dir, void *buf, size_t len,
	     void (*callback)(void *, void *), void *cookie)
{

	if (!ctx) {
		/* XXXrcd: should probably call the callback to free things. */
		return 0;
	}

	return put_stream_userbuf(knc_find_buf(ctx, KNC_SIDE_IN, dir),
	    buf, len, callback, cookie);
}

ssize_t
knc_put_mmapbuf(knc_ctx ctx, int dir, size_t len, int flags, int fd,
		off_t offset)
{

	if (!ctx) {
		errno = ENOMEM;	/* XXXrcd: better error... */
		return -1;
	}

	return put_stream_mmapbuf(knc_find_buf(ctx, KNC_SIDE_IN, dir),
	    len, flags, fd, offset);
}

size_t
knc_get_ibuf(knc_ctx ctx, int dir, void **buf, size_t len)
{

	if (!ctx)
		return 0;

	return get_istream(knc_find_buf(ctx, KNC_SIDE_IN, dir), buf, len);
}

size_t
knc_get_obuf(knc_ctx ctx, int dir, void **buf, size_t len)
{

	if (!ctx)
		return 0;

	return get_ostream(knc_find_buf(ctx, KNC_SIDE_OUT, dir), buf, len);
}

size_t
knc_get_obufv(knc_ctx ctx, int dir, int maxcnt, struct iovec **vec, int *count)
{

	if (!ctx)
		return 0;

	return get_ostreamv(knc_find_buf(ctx,KNC_SIDE_OUT,dir), maxcnt,
	    vec, count);
}

size_t
knc_get_obufc(knc_ctx ctx, int dir, void **buf, size_t len)
{

	if (!ctx)
		return 0;

	return get_ostream_contig(knc_find_buf(ctx, KNC_SIDE_OUT, dir),
	    buf, len);
}

int
knc_put_eof(knc_ctx ctx, int dir)
{
	char	buf[1];

	if (dir == KNC_DIR_SEND) {
		KNCDEBUG((ctx, "putting command: send EOF\n"));
		buf[0] = 0;
		ctx->open &= ~OPEN_WRITE;
	} else {
		KNCDEBUG((ctx, "putting command: recv EOF\n"));
		buf[0] = 1;
	}

	put_stream_command(&ctx->raw_send, buf, 1);
	return 0;
}

int
knc_put_command(knc_ctx ctx, const char *cmd, uint32_t cmdseqno,
		const void *data, uint32_t datalen)
{
	char	*buf;
	char	*tmp;
	size_t	 len = 0;
	size_t	 tlen = 0;

	len = sizeof(cmdseqno) + strlen(cmd) + 1 + sizeof(datalen) + datalen;
	tmp = buf = malloc(len);
	if (!buf)
		return 0;

	cmdseqno = htonl(cmdseqno);
	memcpy(tmp, &cmdseqno, sizeof(cmdseqno));

	tmp += sizeof(cmdseqno);
	tlen += sizeof(cmdseqno);

	strcpy(tmp, cmd);

	tmp += strlen(cmd) + 1;
	tlen += strlen(cmd) + 1;

	datalen = htonl(datalen);
	memcpy(tmp, &datalen, sizeof(datalen));

	tmp += sizeof(datalen);
	tlen += sizeof(datalen);

	datalen = ntohl(datalen);

	if (datalen > 0) {
		memcpy(tmp, data, datalen);
		tlen += datalen;
	}

	assert(tlen == len);

	KNCDEBUG((ctx, "putting command: %s seq=%u\n", cmd, cmdseqno));

	return put_stream_command(&ctx->raw_send, buf, len);
}

size_t
knc_drain_buf(knc_ctx ctx, int dir, size_t len)
{

	if (!ctx)
		return 0;

	return stream_drain(knc_find_buf(ctx, KNC_SIDE_OUT, dir), len);
}

size_t
knc_fill_buf(knc_ctx ctx, int dir, size_t len)
{

	if (!ctx)
		return 0;

	return stream_fill(knc_find_buf(ctx, KNC_SIDE_IN, dir), len);
}

size_t
knc_avail(knc_ctx ctx, int dir)
{

	if (!ctx)
		return 0;

	return stream_avail(knc_find_buf(ctx, KNC_SIDE_OUT, dir));
}

size_t
knc_pending(knc_ctx ctx, int dir)
{
	size_t	ret;

	if (!ctx)
		return 0;

//	if (ctx->state != STATE_SESSION)
//		return 0;

	ret  = stream_avail(knc_find_buf(ctx, KNC_SIDE_OUT, dir));
	ret += stream_avail(knc_find_buf(ctx, KNC_SIDE_IN,  dir));

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
	KNCDEBUG((ctx, "going to get tickets for: %s\n", (char *)name.value));
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

	KNCDEBUG((ctx, "connecting to (%s, %s)...\n", service, domain));

	memset(&ai, 0x0, sizeof(ai));
	ai.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(domain, service, &ai, &res0);
	if (ret) {
		knc_generic_error(ctx, "getaddrinfo: (%s,%s) %s", domain,
		    service, gai_strerror(ret));
		return -1;
	}

	for (res=res0; res; res=res->ai_next) {
		s = get_socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol, flags);
		if (s == -1) {
			KNCDEBUG((ctx, "connect: %s\n", strerror(errno)));
			continue;
		}
		ret = connect(s, res->ai_addr, res->ai_addrlen);
		if (ret != -1)
			break;
		close(s);
		s = -1;
		KNCDEBUG((ctx, "connect: %s\n", strerror(errno)));
	}

	if (s == -1)
		knc_syscall_error(ctx, "connect_host, connect", errno);

	freeaddrinfo(res0);
	return s;
}

/* The Easy Interfaces */

void
knc_garbage_collect(knc_ctx ctx)
{

	if (!ctx)
		return;

	stream_garbage_collect(&ctx->raw_recv);
	stream_garbage_collect(&ctx->raw_send);
	stream_garbage_collect(&ctx->cooked_recv);
	stream_garbage_collect(&ctx->cooked_send);
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
	int		fd = ((struct fd_cookie *)cookie)->wfd;

#ifdef O_NOSIGPIPE
	return writev(fd, iov, iovcnt);
#else
	struct timespec	ts_zero = {0, 0};
	sigset_t	blocked;
	sigset_t	pending;
	sigset_t	sigpipe_mask;
	ssize_t		ret;
	int		my_errno;

	/*
	 * On operating systems which do not have O_NOSIGPIPE, we must
	 * do a bit of a dance to avoid allowing a SIGPIPE to be delivered
	 * outside our control.  Basically, check to see if there's
	 * one pending, if not block SIGPIPE, do the writev(2),
	 * consume any generated SIGPIPE, and restore the old sigmask.
	 */

	sigemptyset(&blocked);
	sigemptyset(&pending);
	sigemptyset(&sigpipe_mask);

	sigaddset(&sigpipe_mask, SIGPIPE);
	sigpending(&pending);

	if (!sigismember(&pending, SIGPIPE))
		pthread_sigmask(SIG_BLOCK, &sigpipe_mask, &blocked);

	ret = writev(fd, iov, iovcnt);
	my_errno = errno;

	if (!sigismember(&pending, SIGPIPE)) {
		int	ret2;

		do {
			ret2 = sigtimedwait(&sigpipe_mask, NULL,
			    &ts_zero);
		} while (ret2 == -1 && errno == EINTR);

		pthread_sigmask(SIG_SETMASK, &blocked, NULL);
	}

	errno = my_errno;
	return ret;
#endif
}

static int
fdclose(void *cookie)
{
	struct fd_cookie	*fdc = cookie;
	int			 mine = fdc->mine;
	int			 rfd = fdc->rfd;
	int			 wfd = fdc->wfd;

	free(cookie);

	if (!mine)
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

	ctx->netcookie = cookie;
	ctx->netread   = fdread;
	ctx->netwritev = fdwritev;
	ctx->netclose  = fdclose;
}

void
knc_give_net_fds(knc_ctx ctx, int rfd, int wfd)
{

	knc_set_net_fds(ctx, rfd, wfd);
	((struct fd_cookie *)ctx->netcookie)->mine = 1;;
}

void
knc_set_net_fd(knc_ctx ctx, int fd)
{

	knc_set_net_fds(ctx, fd, fd);
}

void
knc_give_net_fd(knc_ctx ctx, int fd)
{

	knc_give_net_fds(ctx, fd, fd);
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

	ctx->localcookie = cookie;
	ctx->localread   = fdread;
	ctx->localwritev = fdwritev;
	ctx->localclose  = fdclose;
}

void
knc_give_local_fds(knc_ctx ctx, int rfd, int wfd)
{

	knc_set_local_fds(ctx, rfd, wfd);
	((struct fd_cookie *)ctx->localcookie)->mine = 1;
}

void
knc_set_local_fd(knc_ctx ctx, int fd)
{

	knc_set_local_fds(ctx, fd, fd);
}

void
knc_give_local_fd(knc_ctx ctx, int fd)
{

	knc_give_local_fds(ctx, fd, fd);
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
		return stream_avail(&ctx->cooked_recv) < ctx->recvinbufsiz;

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

nfds_t
knc_get_pollfds(knc_ctx ctx, struct pollfd *fds, knc_callback *cbs,
		nfds_t nfds)
{
	nfds_t	i = 0;

	if (!ctx)
		return 0;

	if (knc_get_net_rfd(ctx) && knc_need_input(ctx, KNC_DIR_RECV)) {
		cbs[i]		= _fill_recv;
		fds[i].fd	= knc_get_net_rfd(ctx);
		fds[i++].events	= POLLIN;
		if (i >= nfds)
			return (nfds_t)-1;
	}

	if (knc_get_net_wfd(ctx) != -1 && knc_can_output(ctx, KNC_DIR_SEND)) {
		cbs[i]		= _flush_send;
		fds[i].fd	= knc_get_net_wfd(ctx);
		fds[i++].events = POLLOUT;
		if (i >= nfds)
			return (nfds_t)-1;
	}

	if (knc_get_local_rfd(ctx) != -1 &&
	    knc_need_input(ctx, KNC_DIR_SEND)) {
		/*
		 * Here, we are reading unframed bytes and so we size our
		 * buffer as the slightly more accurate raw+cooked size for
		 * comparison.
		 */
		cbs[i]		= _fill_send;
		fds[i].fd	 = knc_get_local_rfd(ctx);
		fds[i++].events	 = POLLIN;
		if (i >= nfds)
			return (nfds_t)-1;
	}

	if (knc_get_local_wfd(ctx) != -1 &&
	    knc_can_output(ctx, KNC_DIR_RECV)) {
		cbs[i]		= _flush_recv;
		fds[i].fd	 = knc_get_local_wfd(ctx);
		fds[i++].events	 = POLLOUT;
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

void
run_loop(knc_ctx ctx)
{
	knc_callback	cbs[4];
	struct pollfd	fds[4];
	nfds_t		nfds;
	int		ret;

	nfds = knc_get_pollfds(ctx, fds, cbs, 4);
	/* XXXrcd: should have timeout != -1 */
	ret = poll(fds, nfds, -1);
	if (ret == -1) {
		if (errno != EINTR)
			knc_syscall_error(ctx, "poll", errno);
		return;
	}
	knc_service_pollfds(ctx, fds, cbs, nfds);
	knc_garbage_collect(ctx);
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
	if (fd == -1)
		goto out;

	knc_set_net_fd(ctx, fd);
	((struct fd_cookie *)ctx->netcookie)->mine = 1;
	knc_initiate(ctx);

out:
	free(buf);
	return ctx;
}

static int
errno_switch(knc_ctx ctx, int e, const char *errstr)
{

	switch (e) {
#if EAGAIN != EWOULDBLOCK
	case EWOULDBLOCK:
#endif
	case EINTR:
	case EAGAIN:
		break;

	default:
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
	ssize_t	  ret;

	if (!ctx || ctx->error)
		return EIO;

	if (dir == KNC_DIR_SEND) {
		ourread   =  ctx->localread;
		ourcookie =  ctx->localcookie;
	} else {
		ourread   = ctx->netread;
		ourcookie = ctx->netcookie;
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

	KNCDEBUG((ctx, "knc_fill: about to read %zd bytes.\n", len));

	ret = ourread(ourcookie, tmpbuf, (size_t)len);

	if (ret == -1) {
		KNCDEBUG((ctx, "read error: %s\n", strerror(errno)));
		return errno_switch(ctx, errno, "reading");
	}

	if (ret == 0) {
		KNCDEBUG((ctx, "knc_fill: got EOF\n"));
		/*
		 * XXXrcd: we may very well call this an error because
		 *         we are supposed to see an appropriate command
		 *         packet for close.
		 */
		if (ctx->open & OPEN_READ) {
			knc_generic_error(ctx, "Short input");
			knc_garbage_collect(ctx);
			return EIO;
		}

		return 0;
	}

	if (ret > 0) {
		KNCDEBUG((ctx, "Read %zd bytes\n", ret));
		knc_fill_buf(ctx, dir, (size_t)ret);
	}

	if (dir == KNC_DIR_RECV)
		knc_state_process_in(ctx);

	knc_garbage_collect(ctx);

	return 0;
}

int
knc_flush(knc_ctx ctx, int dir, size_t flushlen)
{
	struct iovec	 *vec;
	int		  iovcnt;
	size_t		  completelen = 0;
	ssize_t		  len;
	size_t		 *total;
	ssize_t		(*ourwritev)(void *, const struct iovec *, int);
	void		 *ourcookie;

	if (!ctx || ctx->error)
		return EIO;

	if (dir == KNC_DIR_SEND) {
		ourwritev =  ctx->netwritev;
		ourcookie =  ctx->netcookie;
		total     = &ctx->sent_tot;
	} else {
		ourwritev =  ctx->localwritev;
		ourcookie =  ctx->localcookie;
		total     = &ctx->recv_tot;
	}

	/* XXXrcd: deal with ctx->open */

	for (;;) {
		if (dir == KNC_DIR_SEND)
			knc_state_process_out(ctx);

		len = knc_get_obufv(ctx, dir, MAX_IOVCNT, &vec, &iovcnt);
		if (len <= 0)
			break;
		KNCDEBUG((ctx, "knc_flush: about to write %zu bytes.\n", len));

		len = ourwritev(ourcookie, vec, iovcnt);

		if (len == -1) {
			KNCDEBUG((ctx, "write error: %s\n", strerror(errno)));
			return errno_switch(ctx, errno, "writev");
		}

		*total += len;
		KNCDEBUG((ctx, "knc_flush: wrote %zd bytes, total=%zd\n",
		    len, *total));
		knc_drain_buf(ctx, dir, (size_t)len);

		knc_garbage_collect(ctx);

		completelen += len;
		if (completelen >= flushlen)
			break;
	}

	return 0;
}

int
knc_shutdown(knc_ctx ctx, int how)
{

	if (!ctx) {
		errno = EBADF;
		return -1;
	}

	if (ctx->error) {
		errno = EIO;
		return -1;
	}

	switch (how) {
	case SHUT_RD:
		if (ctx->open & OPEN_READ)
			knc_put_eof(ctx, KNC_DIR_RECV);
		break;
	case SHUT_WR:
		if (ctx->open & OPEN_WRITE)
			knc_put_eof(ctx, KNC_DIR_SEND);
		break;
	case SHUT_RDWR:
		if (ctx->open & OPEN_READ)
			knc_put_eof(ctx, KNC_DIR_RECV);
		if (ctx->open & OPEN_WRITE)
			knc_put_eof(ctx, KNC_DIR_SEND);
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	/* XXXrcd: should we flush?  Hmmm, maybe not? */
	// knc_flush(ctx, KNC_DIR_SEND, -1);

	/*
	 * XXXrcd: think through a little more... getting off train in
	 *         a few minutes...
	 */

	return 0;
}

int
knc_close(knc_ctx ctx)
{
	int	ret;

	ret = knc_shutdown(ctx, SHUT_RDWR);
	if (ret)
		return ret;

	while (!knc_eof(ctx) && !knc_error(ctx)) {
		run_loop(ctx);
                ret = knc_avail(ctx, KNC_DIR_RECV);

                if (ret > 0)
			knc_drain_buf(ctx, KNC_DIR_RECV, ret);
	}

	return 0;
}

int
knc_eof(knc_ctx ctx)
{

	if (!ctx)
		return 1;

	if ((ctx->open & OPEN_READ) || !knc_pending(ctx, KNC_DIR_SEND))
		return 0;

	return 1;
}

int
knc_io_complete(knc_ctx ctx)
{

	if (!ctx)
		return 1;

	if (ctx->open)
		return 0;

	if (knc_pending(ctx, KNC_DIR_SEND))
		return 0;

	if (knc_pending(ctx, KNC_DIR_RECV))
		return 0;

	return 1;
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

	for (ret = GSS_S_COMPLETE; ret == GSS_S_COMPLETE;) {

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

		if (str)
			newlen = strlen(str);
		else
			newlen = strlen(preamble);

		if (GSS_ERROR(ret)) {
			if (ret == GSS_S_FAILURE)
				newlen += strlen(gen_gss_msg);
			else
				newlen += strlen(bad_gss_msg); /* wat */
			newlen += sizeof("; ") - 1;
		}

		newlen += status.length + 3;

		tmp = str;
		str = malloc(newlen);

		if (!str) {
			free(tmp);
			gss_release_buffer(&new_stat, &status);
			return oom_gss_msg;
		}

		if (GSS_ERROR(ret)) {
			snprintf(str, newlen, "%s; %s%s",
			    (ret == GSS_S_FAILURE)?gen_gss_msg:bad_gss_msg,
			    tmp?tmp:preamble, tmp?", ":": ");
		} else {
			snprintf(str, newlen, "%s%s%.*s", tmp?tmp:preamble,
			    tmp?", ":": ", (int)status.length,
			    (char *)status.value);
		}

		if (!GSS_ERROR(ret))
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

#define GENERIC_BUFSIZ	1024

void
knc_generic_error(knc_ctx ctx, const char *fmt, ...)
{
	va_list ap;

	ctx->error  = KNC_ERROR_GENERIC;
	ctx->errstr = malloc(GENERIC_BUFSIZ);

	if (!ctx->errstr)
		return;

	va_start(ap, fmt);
	vsnprintf(ctx->errstr, GENERIC_BUFSIZ, fmt, ap);
	va_end(ap);
}

void
knc_syscall_error(knc_ctx ctx, const char *str, int number)
{
	char	*errstr;
	char	*tmp;

	/* XXXrcd: wrong type */
	ctx->error = KNC_ERROR_GSS;

	errstr = strerror(number);
	tmp = malloc(strlen(str) + strlen(errstr) + 3);

	if (tmp)
		sprintf(tmp, "%s: %s", str, errstr);

	ctx->errstr = tmp;
}

void
knc_gss_error(knc_ctx ctx, OM_uint32 maj_stat, OM_uint32 min_stat,
	      const char *s)
{
	ctx->error = KNC_ERROR_GSS;

	if (strcmp(s, "gss_process_context_token") == 0 &&
	    maj_stat == GSS_S_COMPLETE) {
		ctx->errstr = strdup("Connection securely closed by peer");
	} else {
		ctx->errstr = knc_errstring(maj_stat, min_stat, s);
		assert( ctx->errstr != NULL );
	}
	KNCDEBUG((ctx, "knc_gss_error: %s\n", ctx->errstr));
}

void
knc_enomem(knc_ctx ctx)
{

	knc_syscall_error(ctx, "Out of memory", ENOMEM);
}
