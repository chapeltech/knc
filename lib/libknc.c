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
#include <limits.h>
#include <malloc.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
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
#include "lz4frame.h"
#include "private.h"

#ifndef USE_STUB_GSS_WRAP 
#define USE_STUB_GSS_WRAP 0
#endif
 
#if USE_STUB_GSS_WRAP
/*
 * This over-rides gss_{,unwrap} with functions that memcpy rather than
 * perform crypto and is intended only for testing.
 */
#include "stubgsswrap.c"
#endif

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

#define STREAM_BIT_ALLOC_UNIT	(64 * 1024)
#define NUM_STREAM_BITS	31
#define NUM_STREAM_BUFS	4

/*
 * Absolute maximum length of a single wire frame body (the uint32_t
 * length prefix is not included).  Peers must not advertise larger
 * frames; we reject them as a protocol error so raw_recv cannot grow
 * without bound before GSS processing.
 */
#define KNC_MAX_WIRELEN		(1024 * 1024)

struct stream {
	struct stream_bit	*head;
	struct stream_bit	*cur;
	struct stream_bit	*tail;
	struct stream_gc	*garbage;
	int			 collecting;	/* g/c is ongoing */
	size_t			 bufpos;
	size_t			 avail;
	uint32_t		 bits_table;
	uint32_t		 bufs_table;
	struct stream_bit	 bits[NUM_STREAM_BITS];
	char			 bufs[NUM_STREAM_BUFS]
				     [STREAM_BIT_ALLOC_UNIT*2];
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
	int			 lz4_request_sent;
	int			 lz4_send_pending;
	int			 lz4_send;
	int			 lz4_recv;
	int			 lz4_send_started;
	int			 lz4_send_ended;
	int			 lz4_flush_pending;
	int			 lz4_recv_started;
	int			 lz4_recv_finished;
	int			 lz4_recv_drain_pending;
	int			 lz4_recv_eof;
	LZ4F_compressionContext_t lz4_send_ctx;
	LZ4F_decompressionContext_t lz4_recv_ctx;
	int			 capabilities_sent;
	int			 max_recv_packet_probed;
	size_t			 local_max_recv_packet;
	size_t			 peer_max_recv_packet;
	int			 error;
	int			 debug;
	char			 debug_prefix[64];
	char			*errstr;

	size_t			 recvinbufsiz;	/* XXXrcd: low water? */
	size_t			 sendinbufsiz;	/* XXXrcd: low water? */

	size_t			 sendmax;	/* XXXrcd: hmmm */
	size_t			 gssmaxpacket;

	struct stream		 raw_recv;
	/*
	 * sushi_* is the session byte stream between local plaintext and
	 * GSS packets.  Optional compression framing lives here; GSS packet
	 * boundaries do not.
	 */
	struct stream		 sushi_recv;
	struct stream		 cooked_recv;
	struct stream		 raw_send;
	struct stream		 sushi_send;
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
	int	rclosed;
	int	wclosed;
};

/* mmm, macros. */

#if __GNUC__ > 2
#define __predict_true(exp)     __builtin_expect((exp) != 0, 1)
#define __predict_false(exp)    __builtin_expect((exp) != 0, 0)
#else
#define __predict_true(exp)     (exp)
#define __predict_false(exp)    (exp)
#endif

#define MAX_IOVCNT	32

#define KNC_GSS_ERROR(_ctx, _maj, _min, _ret, _str) do {		\
		if (__predict_false(GSS_ERROR((_maj)))) {		\
			knc_gss_error((_ctx), (_maj), (_min), (_str));	\
			return _ret;					\
		}							\
	} while (0/*CONSTCOND*/)

#define MIN(a, b)	((a)<(b)?(a):(b))

#ifdef LOW_LEVEL_DEBUGGERY
/* XXXrcd: eventually get rid of DEBUG() */
int debug = 0;
#define DEBUG(x) do {				\
		if (__predict_false(debug)) {	\
			debug_printf x ;	\
		}				\
	} while (0/*CONSTCOND*/)
#else
#define DEBUG(x)
#endif

/* Local function declarations */

static void	debug_printf(knc_ctx, const char *, ...)
    __attribute__((__format__(__printf__, 2, 3)));

static void		 destroy_stream(stream);
static stream_bit	 get_stream_bit(stream);
static void		 rel_stream_bit(stream, stream_bit);
static void		*get_stream_buf(stream, size_t);
static void		 rel_stream_buf(stream, void *);
static stream_bit	 alloc_stream_bit(stream, int, size_t);
static size_t		 append_stream_bit(stream, stream_bit);

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
static size_t	read_packet(knc_ctx, stream, void **b);
static int	put_packet(knc_ctx, gss_buffer_t);
static int	wrap_and_put_packet(knc_ctx, char *, size_t);
static int	wrap_sushi_packet(knc_ctx);
static int	knc_wrap_size_limit(knc_ctx, size_t, size_t *, int);
static size_t	knc_effective_wrap_input_limit(knc_ctx, size_t);
static int	knc_probe_max_recv_packet(knc_ctx);
static int	knc_put_unwrapped_data(knc_ctx, gss_buffer_t);
static int	knc_process_sushi_recv(knc_ctx);
static void	knc_lz4_mark_recv_eof(knc_ctx);
static int	knc_lz4_start_send(knc_ctx);
static int	knc_lz4_compress_data(knc_ctx, void *, size_t);
static int	knc_lz4_flush_send(knc_ctx);
static int	knc_lz4_end_send(knc_ctx);
static int	knc_queue_capabilities(knc_ctx);
static int	knc_queue_lz4_request(knc_ctx);
static void	knc_maybe_enable_lz4_send(knc_ctx, void *, size_t);
static void	free_mallocbuf(void *, void *);

static int	knc_check_ret_flags(knc_ctx);
static int	knc_state_init(knc_ctx, void *, size_t);
static int	knc_state_accept(knc_ctx, void *, size_t);
static int	knc_state_session(knc_ctx, void *, size_t);
static int	knc_state_command(knc_ctx, void *, size_t);
static int	knc_state_process_in(knc_ctx);
static int	knc_state_process_out(knc_ctx);
static void	knc_discard_empty_input(knc_ctx, int);
static void	knc_remote_read_eof(knc_ctx);
static void	knc_remote_write_eof(knc_ctx);
static void	knc_local_read_eof(knc_ctx);
static void	knc_local_write_eof(knc_ctx);
static void	knc_network_read_eof(knc_ctx);
static void	knc_network_write_eof(knc_ctx);
static void	knc_maybe_shutdown_fds(knc_ctx);

static stream	knc_find_buf(knc_ctx, int, int);

/* And, ta da: the code */

static void
knc_debugf(knc_ctx ctx, const char *fmt, ...)
{
	va_list ap;

	if (__predict_true(ctx && !ctx->debug))
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

static stream_bit
get_stream_bit(stream s)
{
	stream_bit	ret;
	size_t		idx;

	idx = ffs(s->bits_table);
	if (!idx)
		return calloc(1, sizeof(*ret));

	idx--;
	s->bits_table &= ~(1 << idx);
	ret = &s->bits[idx];
	memset(ret, 0x0, sizeof(*ret));
	return ret;
}

static void
rel_stream_bit(stream s, stream_bit bit)
{
	uintptr_t	base;
	uintptr_t	ptr;
	size_t	idx;

	base = (uintptr_t)&s->bits[0];
	ptr = (uintptr_t)bit;
	if (ptr < base || ptr - base >= sizeof(s->bits)) {
		free(bit);
		return;
	}
	if ((ptr - base) % sizeof(s->bits[0]) != 0)
		return;

	idx = (ptr - base) / sizeof(s->bits[0]);
	s->bits_table |= 1 << idx;
}

static void *
get_stream_buf(stream s, size_t len)
{
	size_t	idx;

	if (len > 2 * STREAM_BIT_ALLOC_UNIT)
		return calloc(len, 1);

	idx = ffs(s->bufs_table);
	if (!idx)
		return calloc(len, 1);

	idx--;
	s->bufs_table &= ~(1 << idx);
	memset(&s->bufs[idx], 0x0, len);
	return &s->bufs[idx];
}

static void
rel_stream_buf(stream s, void *buf)
{
	uintptr_t	base;
	uintptr_t	ptr;
	size_t		d;
	size_t		idx;

	base = (uintptr_t)&s->bufs[0][0];
	ptr = (uintptr_t)buf;
	if (ptr < base || ptr - base >= sizeof(s->bufs)) {
		/* This isn't one of ours, free it. */
		free(buf);
		return;
	}

	d = ptr - base;
	if (d % sizeof(s->bufs[0]) != 0)
		return;

	idx = d / sizeof(s->bufs[0]);

	s->bufs_table |= 1 << idx;
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

static stream_bit
alloc_stream_bit(stream s, int type, size_t len)
{
	stream_bit	 bit;

	if (len == 0)
		return NULL;
	len = MIN((2 * STREAM_BIT_ALLOC_UNIT), len);
	len = ((len + STREAM_BIT_ALLOC_UNIT - 1) / STREAM_BIT_ALLOC_UNIT) *
	    STREAM_BIT_ALLOC_UNIT;

	bit = get_stream_bit(s);
	if (!bit)
		return NULL;

	bit->type	= type;
	bit->buf	= get_stream_buf(s, len);
	bit->len	= 0;
	bit->allocated	= len;

	if (!bit->buf) {
		rel_stream_bit(s, bit);
		return NULL;
	}

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

		buf    = ((const char *)buf) + ret;
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

	bit = get_stream_bit(s);
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

/*ARGSUSED*/
static void
free_mallocbuf(void *buf, void *cookie)
{

	free(buf);
}

static size_t
put_stream_gssbuf(stream s, gss_buffer_t inbuf)
{
	gss_buffer_t	buf;
	size_t		ret;

	buf = calloc(1, sizeof(*buf));
	if (!buf)
		/* XXXrcd: raise an error here? */
		return 0;

	buf->value  = inbuf->value;
	buf->length = inbuf->length;

	ret = put_stream_userbuf(s, buf->value, buf->length, free_gssbuf, buf);
	if (ret != buf->length)
		free(buf);
	return ret;
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

	tmp = get_stream_bit(s);
	if (!tmp)
		return 0;
	tmp->buf = get_stream_buf(s, len);
	if (!tmp->buf) {
		rel_stream_bit(s, tmp);
		return 0;
	}

	if (len > 0)
		memcpy(tmp->buf, buf, len);
	tmp->type = STREAM_COMMAND;
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

	if (s->cur && s->tail) {
		remaining = s->tail->allocated - s->tail->len;

		if (remaining >= len) {
			*buf = (void *)((char *)s->tail->buf + s->tail->len);
			return MIN(len, remaining);
		}
	}

	tmp = alloc_stream_bit(s, STREAM_BUFFER, len);
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
	int		bitcnt;
	int		i;
	size_t		len;

	if (vec)
		*vec = NULL;
	if (count)
		*count = 0;
	if (!s || !s->cur || !vec || !count || maxcnt <= 0)
		/* Nothing here */
		return 0;

	/*
	 * XXXrcd: error if the stream bit is a command?  Shouldn't happen,
	 *         though because the user is not exposed to such streams
	 *         and the internal code doesn't use this func.
	 */

	/* First we count the bits. */

	bitcnt = 0;
	for (cur = s->cur; cur && bitcnt < maxcnt; cur = cur->next)
		++bitcnt;

	*vec = malloc(bitcnt * sizeof(**vec));
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

	for (cur = cur->next; cur && i < bitcnt; cur = cur->next) {
		(*vec)[i].iov_base = cur->buf;
		(*vec)[i].iov_len  = cur->len;
		len += cur->len;
		DEBUG((NULL, "creating iovec element of length %zu, "
		    "total %zu\n", cur->len, len));
		++i;
	}

	*count = i;
	if (stream_put_trash(s, *vec) < 0) {
		free(*vec);
		*vec = NULL;
		*count = 0;
		return 0;
	}

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
	int		type;
	size_t		retlen;
	size_t		tmplen;

	if (!s || !s->cur)
		return 0;

	/* Commands are stream boundaries, not bytes in the adjacent buffer. */

	type = s->cur->type;
	tmplen = s->cur->len - s->bufpos;
	for (cur = s->cur->next; cur && cur->type == type;
	    cur = cur->next)
		tmplen += cur->len;
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
	if (stream_put_trash(s, *buf) < 0) {
		free(*buf);
		*buf = NULL;
		return 0;
	}

	retlen = 0;
	cur = s->cur;

	retlen = cur->len - s->bufpos;
	memcpy(*buf, (char *)cur->buf + s->bufpos, retlen);
	cur = cur->next;

	while (retlen < len && cur && cur->type == type) {
		tmplen = MIN(len - retlen, cur->len);
		memcpy((char *)*buf + retlen, cur->buf, tmplen);

		cur = cur->next;
		retlen += tmplen;
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
			rel_stream_buf(s, s->head->buf);

		rel_stream_bit(s, s->head);
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

#define KNC_DEFAULT_MAX_RECV_PACKET	(64 * 1024)
#define KNC_PACKET_GRACE_NYBBLES	512
#define KNC_PACKET_GRACE		(KNC_PACKET_GRACE_NYBBLES / 2)
#define KNC_WRAP_LIMIT_SEARCH_STEP	256
#define KNC_WRAP_LIMIT_SEARCH_MAX	(16 * 1024)

#define KNC_LZ4_INPUT_CHUNK	(64 * 1024)
#define KNC_LZ4_OUTPUT_CHUNK	(64 * 1024)

#define KNC_CMD_CAPABILITY	"capability"
#define KNC_CMD_LZ4_REQUEST	"compress_lz4"
#define KNC_CMD_LZ4_ACK		"compress_lz4_ok"

static size_t
packet_limit_with_grace(size_t limit)
{

	if (limit > SIZE_MAX - KNC_PACKET_GRACE)
		return SIZE_MAX;

	return limit + KNC_PACKET_GRACE;
}

static size_t
read_packet(knc_ctx ctx, stream s, void **buf)
{
	size_t		 len;
	size_t		 maxlen;
	size_t		 need;
	uint32_t	 wirelen;
	void		*tmp;

	DEBUG((NULL, "read_packet: enter\n"));

	if (get_ostream_contig(s, &tmp, 4) < 4)
		return 0;

	memcpy(&wirelen, tmp, sizeof(wirelen));
	wirelen = ntohl(wirelen);
	maxlen = packet_limit_with_grace(ctx->local_max_recv_packet);

	DEBUG((NULL, "read_packet: got wirelen = %u\n", wirelen));

	/*
	 * Bound wire frames so a peer cannot force unbounded raw_recv
	 * growth.  Also reject length + 4 if it would overflow size_t.
	 */
	if (wirelen > KNC_MAX_WIRELEN || wirelen > maxlen ||
	    (size_t)wirelen > (size_t)-1 - 4) {
		knc_proto_error(ctx, "Wire frame too large (%u)",
		    (unsigned)wirelen);
		return 0;
	}

	need = (size_t)wirelen + 4;
	if (stream_avail(s) < need)
		return 0;

	stream_drain(s, 4);

	/* Okay, now we know that we've got an entire packet */

	DEBUG((NULL, "read_packet: getting %u bytes\n", wirelen));
	len = get_ostream_contig(s, buf, wirelen);

	if (len != wirelen) {
		knc_enomem(ctx);
		return 0;
	}

	stream_drain(s, len);

	DEBUG((NULL, "read_packet: %zu left in stream\n", s->avail));
	/* XXXrcd: broken, I think. */

	return len;
}

static int
knc_wrap_size_limit(knc_ctx ctx, size_t wire_limit, size_t *plain_limit,
    int set_error)
{
	OM_uint32	 maj;
	OM_uint32	 min;
	OM_uint32	 input_size;
	OM_uint32	 output_size;
	int		 privacy = (ctx->opts & KNC_OPT_NOPRIVACY)?0:1;

	if (wire_limit > UINT32_MAX)
		output_size = UINT32_MAX;
	else
		output_size = (OM_uint32)wire_limit;

	maj = gss_wrap_size_limit(&min, ctx->gssctx, privacy,
	    GSS_C_QOP_DEFAULT, output_size, &input_size);

	if (maj != GSS_S_COMPLETE) {
		if (set_error)
			knc_gss_error(ctx, maj, min, "gss_wrap_size_limit");
		return -1;
	}

	*plain_limit = input_size;
	return 0;
}

static size_t
knc_effective_wrap_input_limit(knc_ctx ctx, size_t wanted)
{
	size_t	limit;

	if (knc_wrap_size_limit(ctx, ctx->peer_max_recv_packet, &limit, 1) < 0)
		return 0;

	return MIN(wanted, limit);
}

static int
knc_probe_max_recv_packet(knc_ctx ctx)
{
	size_t	plain_limit;
	size_t	wire_limit;
	size_t	max_wire_limit;

	if (ctx->max_recv_packet_probed)
		return 0;

	ctx->max_recv_packet_probed = 1;
	wire_limit = KNC_DEFAULT_MAX_RECV_PACKET;
	max_wire_limit = KNC_DEFAULT_MAX_RECV_PACKET + KNC_WRAP_LIMIT_SEARCH_MAX;

	while (wire_limit <= max_wire_limit) {
		if (knc_wrap_size_limit(ctx, wire_limit, &plain_limit, 0) < 0)
			return -1;
		if (plain_limit >= KNC_DEFAULT_MAX_RECV_PACKET) {
			if (ctx->local_max_recv_packet < wire_limit)
				ctx->local_max_recv_packet = wire_limit;
			return 0;
		}
		wire_limit += KNC_WRAP_LIMIT_SEARCH_STEP;
	}

	return -1;
}

static int
put_packet(knc_ctx ctx, gss_buffer_t buf)
{
	uint32_t	netlen;

	if (buf->length > ctx->peer_max_recv_packet ||
	    buf->length > UINT32_MAX) {
		knc_proto_error(ctx, "Wrapped packet exceeds peer limit");
		return -1;
	}

	netlen = htonl((uint32_t)buf->length);
	if (put_stream(&ctx->cooked_send, &netlen, 4) != 4 ||
	    put_stream_gssbuf(&ctx->cooked_send, buf) != buf->length) {
		knc_enomem(ctx);
		return -1;
	}

	return 0;
}

static int
wrap_and_put_packet(knc_ctx ctx, char *buf, size_t len)
{
	gss_buffer_desc	 in;
	gss_buffer_desc	 out;
	OM_uint32	 maj;
	OM_uint32	 min;
	int		 conf_state = 0;
	int		 privacy = (ctx->opts & KNC_OPT_NOPRIVACY)?0:1;

	in.length = len;
	in.value  = buf;
	maj = gss_wrap(&min, ctx->gssctx, privacy, GSS_C_QOP_DEFAULT,
	    &in, &conf_state, &out);

	KNC_GSS_ERROR(ctx, maj, min, -1, "gss_wrap");

	if (privacy && !conf_state) {
		knc_proto_error(ctx, "gss_wrap did not provide confidentiality");
		gss_release_buffer(&min, &out);
		return 0;
	}

	return put_packet(ctx, &out);
}

static void
knc_lz4_preferences(LZ4F_preferences_t *prefs)
{

	memset(prefs, 0, sizeof(*prefs));
	prefs->frameInfo.blockSizeID = LZ4F_max64KB;
	prefs->frameInfo.blockMode = LZ4F_blockLinked;
	prefs->compressionLevel = 0;
	prefs->autoFlush = 0;
}

static int
knc_lz4_error(knc_ctx ctx, size_t code, const char *what)
{

	if (!LZ4F_isError(code))
		return 0;

	knc_proto_error(ctx, "%s: %s", what, LZ4F_getErrorName(code));
	return -1;
}

static int
put_malloc_stream(knc_ctx ctx, stream s, void *buf, size_t len)
{

	if (len == 0) {
		free(buf);
		return 0;
	}

	if (put_stream_userbuf(s, buf, len, free_mallocbuf, NULL) == len)
		return 0;

	free(buf);
	knc_enomem(ctx);
	return -1;
}

static int
knc_lz4_start_send(knc_ctx ctx)
{
	LZ4F_preferences_t	 prefs;
	void			*buf;
	size_t			 ret;

	if (ctx->lz4_send_started)
		return 0;

	if (ctx->lz4_send_ended) {
		knc_proto_error(ctx, "LZ4 data after compression end");
		return -1;
	}

	if (!ctx->lz4_send_ctx) {
		ret = LZ4F_createCompressionContext(&ctx->lz4_send_ctx,
		    LZ4F_VERSION);
		if (knc_lz4_error(ctx, ret,
		    "LZ4F_createCompressionContext") < 0)
			return -1;
	}

	buf = malloc(LZ4F_HEADER_SIZE_MAX);
	if (!buf) {
		knc_enomem(ctx);
		return -1;
	}

	knc_lz4_preferences(&prefs);
	ret = LZ4F_compressBegin(ctx->lz4_send_ctx, buf,
	    LZ4F_HEADER_SIZE_MAX, &prefs);
	if (knc_lz4_error(ctx, ret, "LZ4F_compressBegin") < 0) {
		free(buf);
		return -1;
	}

	ctx->lz4_send_started = 1;
	return put_malloc_stream(ctx, &ctx->sushi_send, buf, ret);
}

static int
knc_lz4_compress_data(knc_ctx ctx, void *inbuf, size_t len)
{
	LZ4F_compressOptions_t	 opts;
	LZ4F_preferences_t	 prefs;
	void			*outbuf;
	size_t			 cap;
	size_t			 ret;

	if (knc_lz4_start_send(ctx) < 0)
		return -1;

	knc_lz4_preferences(&prefs);
	cap = LZ4F_compressBound(len, &prefs);
	outbuf = malloc(cap);
	if (!outbuf) {
		knc_enomem(ctx);
		return -1;
	}

	memset(&opts, 0, sizeof(opts));
	ret = LZ4F_compressUpdate(ctx->lz4_send_ctx, outbuf, cap,
	    inbuf, len, &opts);
	if (knc_lz4_error(ctx, ret, "LZ4F_compressUpdate") < 0) {
		free(outbuf);
		return -1;
	}

	ctx->lz4_flush_pending = 1;
	return put_malloc_stream(ctx, &ctx->sushi_send, outbuf, ret);
}

static int
knc_lz4_flush_send(knc_ctx ctx)
{
	LZ4F_compressOptions_t	 opts;
	LZ4F_preferences_t	 prefs;
	void			*buf;
	size_t			 cap;
	size_t			 ret;

	if (!ctx->lz4_flush_pending || !ctx->lz4_send_started)
		return 0;

	knc_lz4_preferences(&prefs);
	cap = LZ4F_compressBound(0, &prefs);
	buf = malloc(cap);
	if (!buf) {
		knc_enomem(ctx);
		return -1;
	}

	memset(&opts, 0, sizeof(opts));
	ret = LZ4F_flush(ctx->lz4_send_ctx, buf, cap, &opts);
	if (knc_lz4_error(ctx, ret, "LZ4F_flush") < 0) {
		free(buf);
		return -1;
	}

	ctx->lz4_flush_pending = 0;
	return put_malloc_stream(ctx, &ctx->sushi_send, buf, ret);
}

static int
knc_lz4_end_send(knc_ctx ctx)
{
	LZ4F_compressOptions_t	 opts;
	LZ4F_preferences_t	 prefs;
	void			*buf;
	size_t			 cap;
	size_t			 ret;

	if (ctx->lz4_send_ended)
		return 0;

	if (!ctx->lz4_send_started) {
		ctx->lz4_send_ended = 1;
		ctx->lz4_flush_pending = 0;
		return 0;
	}

	knc_lz4_preferences(&prefs);
	cap = LZ4F_compressBound(0, &prefs);
	buf = malloc(cap);
	if (!buf) {
		knc_enomem(ctx);
		return -1;
	}

	memset(&opts, 0, sizeof(opts));
	ret = LZ4F_compressEnd(ctx->lz4_send_ctx, buf, cap, &opts);
	if (knc_lz4_error(ctx, ret, "LZ4F_compressEnd") < 0) {
		free(buf);
		return -1;
	}

	ctx->lz4_send_ended = 1;
	ctx->lz4_flush_pending = 0;
	return put_malloc_stream(ctx, &ctx->sushi_send, buf, ret);
}

static int
wrap_sushi_packet(knc_ctx ctx)
{
	size_t		 len;
	size_t		 limit;
	void		*buf;

	switch (knc_get_stream_bit_type(&ctx->sushi_send)) {
	case STREAM_COMMAND:
		buf = knc_get_stream_command(&ctx->sushi_send, &len);
		if (wrap_and_put_packet(ctx, buf, 0) < 0)
			return -1;
		if (wrap_and_put_packet(ctx, buf, len) < 0)
			return -1;
		knc_maybe_enable_lz4_send(ctx, buf, len);
		return 1;

	case STREAM_BUFFER:
		limit = knc_effective_wrap_input_limit(ctx, ctx->gssmaxpacket);
		if (limit < 1)
			return -1;

		len = get_ostream_contig(&ctx->sushi_send, &buf, limit);
		if (len < 1)
			return 0;

		if (wrap_and_put_packet(ctx, buf, len) < 0)
			return -1;
		stream_drain(&ctx->sushi_send, len);
		return 1;

	default:
		break;
	}

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
	ret->req_mech		= GSS_C_NO_OID;
	ret->ret_mech		= GSS_C_NO_OID;
	ret->req_flags		= GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG |
				  GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG;
	ret->deleg_cred		= GSS_C_NO_CREDENTIAL;

	ret->open = OPEN_READ|OPEN_WRITE;
	ret->locally_initiated	= 0;

	ret->recvinbufsiz = 16384;
	ret->sendinbufsiz = 65536;
	ret->sendmax      = 65536;
	ret->gssmaxpacket = 65536;
	ret->local_max_recv_packet = KNC_DEFAULT_MAX_RECV_PACKET;
	ret->peer_max_recv_packet  = KNC_DEFAULT_MAX_RECV_PACKET;

	ret->raw_recv.bits_table    = ((uint32_t)1 << NUM_STREAM_BITS) - 1;
	ret->sushi_recv.bits_table  = ((uint32_t)1 << NUM_STREAM_BITS) - 1;
	ret->raw_send.bits_table    = ((uint32_t)1 << NUM_STREAM_BITS) - 1;
	ret->sushi_send.bits_table  = ((uint32_t)1 << NUM_STREAM_BITS) - 1;
	ret->cooked_recv.bits_table = ((uint32_t)1 << NUM_STREAM_BITS) - 1;
	ret->cooked_send.bits_table = ((uint32_t)1 << NUM_STREAM_BITS) - 1;

	ret->raw_recv.bufs_table    = ((uint32_t)1 << NUM_STREAM_BUFS) - 1;
	ret->sushi_recv.bufs_table  = ((uint32_t)1 << NUM_STREAM_BUFS) - 1;
	ret->raw_send.bufs_table    = ((uint32_t)1 << NUM_STREAM_BUFS) - 1;
	ret->sushi_send.bufs_table  = ((uint32_t)1 << NUM_STREAM_BUFS) - 1;
	ret->cooked_recv.bufs_table = ((uint32_t)1 << NUM_STREAM_BUFS) - 1;
	ret->cooked_send.bufs_table = ((uint32_t)1 << NUM_STREAM_BUFS) - 1;

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

	free(ctx->errstr);
	LZ4F_freeCompressionContext(ctx->lz4_send_ctx);
	LZ4F_freeDecompressionContext(ctx->lz4_recv_ctx);

	destroy_stream(&ctx->raw_recv);
	destroy_stream(&ctx->sushi_recv);
	destroy_stream(&ctx->cooked_recv);
	destroy_stream(&ctx->raw_send);
	destroy_stream(&ctx->sushi_send);
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
	case KNC_OPT_NO_HALF_CLOSE:
	case KNC_OPT_SENDCMDS:
	case KNC_OPT_COMPRESS_LZ4:
	case KNC_SOCK_NONBLOCK:
	case KNC_SOCK_CLOEXEC:
		return (ctx->opts & opt) ? 1 : 0;

	case KNC_OPT_SENDINBUFSIZ:
		return (int)ctx->sendinbufsiz;
	case KNC_OPT_RECVINBUFSIZ:
		return (int)ctx->recvinbufsiz;
	case KNC_OPT_MAX_RECV_PACKET:
		return (int)ctx->local_max_recv_packet;
	case KNC_OPT_MAX_SEND_PACKET:
		return (int)ctx->gssmaxpacket;

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
	case KNC_OPT_NO_HALF_CLOSE:
	case KNC_OPT_SENDCMDS:
	case KNC_OPT_COMPRESS_LZ4:
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

	case KNC_OPT_MAX_RECV_PACKET:
		if (value > KNC_DEFAULT_MAX_RECV_PACKET) {
			ctx->local_max_recv_packet = value;
			ctx->opts |= KNC_OPT_SENDCMDS;
			ctx->capabilities_sent = 0;
		}
		break;

	case KNC_OPT_MAX_SEND_PACKET:
		if (value > 0)
			ctx->gssmaxpacket = value;
		break;

	default:
		break;
	}

	/* Some options require additional actions: */

	switch (opt) {
	case KNC_OPT_COMPRESS_LZ4:
		if (value)
			ctx->opts |= KNC_OPT_SENDCMDS;
		else {
			ctx->lz4_request_sent = 0;
			ctx->lz4_send_pending = 0;
			ctx->lz4_send = 0;
			ctx->lz4_recv = 0;
			ctx->lz4_send_started = 0;
			ctx->lz4_send_ended = 0;
			ctx->lz4_flush_pending = 0;
			ctx->lz4_recv_started = 0;
			ctx->lz4_recv_finished = 0;
			ctx->lz4_recv_drain_pending = 0;
			ctx->lz4_recv_eof = 0;
			LZ4F_freeCompressionContext(ctx->lz4_send_ctx);
			LZ4F_freeDecompressionContext(ctx->lz4_recv_ctx);
			ctx->lz4_send_ctx = NULL;
			ctx->lz4_recv_ctx = NULL;
		}
		break;
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

	if (ctx->inq_service == GSS_C_NO_NAME) {
		maj = gss_inquire_context(&min, ctx->gssctx, NULL,
		    &ctx->inq_service, NULL, NULL, NULL, NULL, NULL);
		KNC_GSS_ERROR(ctx, maj, min, GSS_C_NO_NAME,
		    "gss_inquire_context");
	}

	return ctx->inq_service;
}

static int
knc_copy_display_buffer(knc_ctx ctx, gss_buffer_t gssbuf, char **display,
    size_t *display_len)
{
	char	*copy;

	if (gssbuf->value == NULL || gssbuf->length == 0 ||
	    gssbuf->length == SIZE_MAX) {
		knc_proto_error(ctx, "GSS display name has invalid length");
		errno = EINVAL;
		return -1;
	}

	copy = malloc(gssbuf->length + 1);
	if (!copy) {
		knc_enomem(ctx);
		errno = ENOMEM;
		return -1;
	}
	memcpy(copy, gssbuf->value, gssbuf->length);
	copy[gssbuf->length] = '\0';
	*display = copy;
	*display_len = gssbuf->length;
	return 0;
}

static int
knc_display_name(knc_ctx ctx, gss_name_t name, char **display,
    size_t *display_len)
{
	gss_buffer_desc	 out = GSS_C_EMPTY_BUFFER;
	OM_uint32	 maj;
	OM_uint32	 min;
	int		 ret;

	if (!ctx || !display || !display_len || name == GSS_C_NO_NAME) {
		errno = EINVAL;
		return -1;
	}
	*display = NULL;
	*display_len = 0;

	maj = gss_display_name(&min, name, &out, NULL);
	KNC_GSS_ERROR(ctx, maj, min, -1, "gss_display_name");
	ret = knc_copy_display_buffer(ctx, &out, display, display_len);
	gss_release_buffer(&min, &out);
	return ret;
}

int
knc_get_client_display_name(knc_ctx ctx, char **display, size_t *display_len)
{
	gss_name_t	name;

	name = knc_get_client(ctx);
	if (name == GSS_C_NO_NAME)
		return -1;
	return knc_display_name(ctx, name, display, display_len);
}

int
knc_get_service_display_name(knc_ctx ctx, char **display, size_t *display_len)
{
	gss_name_t	name;

	name = knc_get_service(ctx);
	if (name == GSS_C_NO_NAME)
		return -1;
	return knc_display_name(ctx, name, display, display_len);
}

int
knc_get_mech_display_name(knc_ctx ctx, char **display, size_t *display_len)
{
	gss_buffer_desc	 out = GSS_C_EMPTY_BUFFER;
	OM_uint32	 maj;
	OM_uint32	 min;
	int		 ret;

	if (!ctx || !display || !display_len || !knc_is_authenticated(ctx) ||
	    ctx->ret_mech == GSS_C_NO_OID) {
		errno = EINVAL;
		return -1;
	}
	*display = NULL;
	*display_len = 0;

	maj = gss_oid_to_str(&min, ctx->ret_mech, &out);
	KNC_GSS_ERROR(ctx, maj, min, -1, "gss_oid_to_str");
	ret = knc_copy_display_buffer(ctx, &out, display, display_len);
	gss_release_buffer(&min, &out);
	return ret;
}

void
knc_free_display_name(char *display)
{

	free(display);
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

/*
 * Only protocol-affecting options cross a process boundary with a security
 * context.  Descriptor flags are properties of the descriptor transferred by
 * the caller and are set independently in the receiving process.
 */
#define KNC_TRANSFER_OPTS (KNC_OPT_NOPRIVACY | KNC_OPT_SENDCMDS)
#define KNC_MAX_EXPORTED_CONTEXT (1024 * 1024)

static int
knc_transfer_streams_empty(knc_ctx ctx)
{

	return stream_avail(&ctx->raw_recv) == 0 &&
	    stream_avail(&ctx->cooked_recv) == 0 &&
	    stream_avail(&ctx->raw_send) == 0 &&
	    stream_avail(&ctx->cooked_send) == 0;
}

int
knc_export_sec_context(knc_ctx ctx, void **token, size_t *token_len,
    unsigned *opts)
{
	gss_buffer_desc	 out = GSS_C_EMPTY_BUFFER;
	OM_uint32	 maj;
	OM_uint32	 min;
	int		 ret;

	if (!ctx || !token || !token_len || !opts) {
		errno = EINVAL;
		return -1;
	}

	*token = NULL;
	*token_len = 0;
	*opts = 0;

	if (ctx->error) {
		errno = EIO;
		return -1;
	}

	if (ctx->state != STATE_SESSION) {
		knc_proto_error(ctx, "GSS context is not at the transferable "
		    "post-authentication boundary");
		errno = EBUSY;
		return -1;
	}

	if (ctx->deleg_cred != GSS_C_NO_CREDENTIAL) {
		knc_proto_error(ctx, "delegated credentials cannot be transferred");
		errno = ENOTSUP;
		return -1;
	}

	/*
	 * cooked_send may contain the acceptor's final authentication token.
	 * Every other queue must already be empty: its presence would mean that
	 * application data, a partial record, or a command has crossed the
	 * ownership boundary.
	 */
	if (stream_avail(&ctx->raw_recv) != 0 ||
	    stream_avail(&ctx->cooked_recv) != 0 ||
	    stream_avail(&ctx->raw_send) != 0) {
		knc_proto_error(ctx, "connexion has buffered data at GSS context "
		    "export");
		errno = EBUSY;
		return -1;
	}

	ret = knc_flush(ctx, KNC_DIR_SEND, (size_t)-1);
	if (ret != 0) {
		errno = ret;
		return -1;
	}
	knc_garbage_collect(ctx);

	if (!knc_transfer_streams_empty(ctx)) {
		knc_proto_error(ctx, "connexion has buffered data after flushing "
		    "the final authentication token");
		errno = EBUSY;
		return -1;
	}

	maj = gss_export_sec_context(&min, &ctx->gssctx, &out);
	KNC_GSS_ERROR(ctx, maj, min, -1, "gss_export_sec_context");

	ctx->state = STATE_UNKNOWN;
	if (out.value == NULL || out.length == 0 ||
	    out.length > KNC_MAX_EXPORTED_CONTEXT) {
		gss_release_buffer(&min, &out);
		knc_proto_error(ctx, "exported GSS context has invalid length");
		errno = EOVERFLOW;
		return -1;
	}
	*token = out.value;
	*token_len = out.length;
	*opts = (unsigned)ctx->opts & KNC_TRANSFER_OPTS;
	return 0;
}

int
knc_import_sec_context(knc_ctx ctx, const void *token, size_t token_len,
    unsigned opts)
{
	gss_buffer_desc	 in;
	gss_name_t	 source = GSS_C_NO_NAME;
	gss_name_t	 target = GSS_C_NO_NAME;
	OM_uint32	 maj;
	OM_uint32	 min;
	OM_uint32	 inquire_min;
	OM_uint32	 delete_min;
	OM_uint32	 lifetime;
	OM_uint32	 flags;
	gss_OID		 mech = GSS_C_NO_OID;
	int		 initiated;
	int		 open;

	if (!ctx || !token || token_len == 0 ||
	    token_len > KNC_MAX_EXPORTED_CONTEXT ||
	    (opts & ~KNC_TRANSFER_OPTS)) {
		errno = EINVAL;
		return -1;
	}

	if (ctx->error || ctx->state != STATE_UNKNOWN ||
	    ctx->gssctx != GSS_C_NO_CONTEXT || !knc_transfer_streams_empty(ctx)) {
		knc_proto_error(ctx, "libknc context is not fresh at GSS context "
		    "import");
		errno = EBUSY;
		return -1;
	}

	in.value = (void *)token;
	in.length = token_len;
	maj = gss_import_sec_context(&min, &in, &ctx->gssctx);
	KNC_GSS_ERROR(ctx, maj, min, -1, "gss_import_sec_context");

	maj = gss_inquire_context(&min, ctx->gssctx, &source, &target,
	    &lifetime, &mech, &flags, &initiated, &open);
	if (GSS_ERROR(maj)) {
		inquire_min = min;
		gss_delete_sec_context(&delete_min, &ctx->gssctx,
		    GSS_C_NO_BUFFER);
		knc_gss_error(ctx, maj, inquire_min, "gss_inquire_context");
		return -1;
	}

	if (!open) {
		gss_release_name(&min, &source);
		gss_release_name(&min, &target);
		gss_delete_sec_context(&min, &ctx->gssctx, GSS_C_NO_BUFFER);
		knc_proto_error(ctx, "imported GSS context is not open");
		errno = EINVAL;
		return -1;
	}

	ctx->opts = (ctx->opts & ~KNC_TRANSFER_OPTS) |
	    ((int)opts & KNC_TRANSFER_OPTS);
	ctx->client = source;
	ctx->inq_service = target;
	ctx->ret_mech = mech;
	ctx->ret_flags = flags;
	ctx->time_rec = lifetime;
	ctx->locally_initiated = initiated;

	if (knc_check_ret_flags(ctx) < 0) {
		gss_delete_sec_context(&min, &ctx->gssctx, GSS_C_NO_BUFFER);
		return -1;
	}

	ctx->state = STATE_SESSION;
	return 0;
}

void
knc_release_exported_sec_context(void *token, size_t token_len)
{
	gss_buffer_desc	 buf;
	OM_uint32	 min;
	volatile unsigned char *p;
	size_t		 left;

	if (!token)
		return;

	p = token;
	left = token_len;
	while (left-- > 0)
		*p++ = 0;
	buf.value = token;
	buf.length = token_len;
	gss_release_buffer(&min, &buf);
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

/*
 * Man page promises mutual auth, integrity, and (unless NOPRIVACY)
 * confidentiality.  Enforce that the established context actually
 * provides those services.
 */
static int
knc_check_ret_flags(knc_ctx ctx)
{
	OM_uint32	need;

	need = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_INTEG_FLAG;
	if (!(ctx->opts & KNC_OPT_NOPRIVACY))
		need |= GSS_C_CONF_FLAG;

	if ((ctx->ret_flags & need) != need) {
		knc_proto_error(ctx, "GSS context missing required flags "
		    "(got 0x%x, need 0x%x)", (unsigned)ctx->ret_flags,
		    (unsigned)need);
		return -1;
	}

	return 0;
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

	knc_debugf(ctx, "knc_state_init: enter\n");
	ctx->locally_initiated = 1;
	maj = gss_init_sec_context(&min, ctx->cred, &ctx->gssctx,
	    ctx->service, ctx->req_mech, ctx->req_flags, ctx->time_req,
	    ctx->cb, &in, &ctx->ret_mech, &out, &ctx->ret_flags,
	    &ctx->time_rec);

	if (out.length > 0)
		put_packet(ctx, &out);
		/* XXXrcd: errors? */

	KNC_GSS_ERROR(ctx, maj, min, -1, "gss_init_sec_context");

	if (!(maj & GSS_S_CONTINUE_NEEDED)) {
		if (knc_check_ret_flags(ctx) < 0)
			return -1;
		ctx->state = STATE_SESSION;
	}

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

	knc_debugf(ctx, "knc_state_accept: enter\n");

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

	if (!(maj & GSS_S_CONTINUE_NEEDED)) {
		if (knc_check_ret_flags(ctx) < 0)
			return -1;
		ctx->state = STATE_SESSION;
	}

	return 0;
}

static int
knc_put_unwrapped_data(knc_ctx ctx, gss_buffer_t out)
{
	size_t	len;

	if (!(ctx->open & OPEN_READ)) {
		knc_proto_error(ctx, "Data after EOF");
		return -1;
	}

	len = out->length;
	if (ctx->lz4_recv) {
		if (ctx->lz4_recv_finished) {
			knc_proto_error(ctx, "LZ4 data after compression end");
			return -1;
		}
		if (put_stream_gssbuf(&ctx->sushi_recv, out) != len) {
			knc_enomem(ctx);
			return -1;
		}
		out->value = NULL;
		out->length = 0;
		return knc_process_sushi_recv(ctx);
	}

	if (put_stream_gssbuf(&ctx->cooked_recv, out) != len) {
		knc_enomem(ctx);
		return -1;
	}
	out->value = NULL;
	out->length = 0;
	return 0;
}

static int
knc_lz4_start_recv(knc_ctx ctx)
{

	if (ctx->lz4_recv_ctx)
		return 0;

	return knc_lz4_error(ctx,
	    LZ4F_createDecompressionContext(&ctx->lz4_recv_ctx,
	    LZ4F_VERSION), "LZ4F_createDecompressionContext");
}

static int
knc_process_sushi_recv(knc_ctx ctx)
{
	LZ4F_decompressOptions_t	 opts;
	void			*src;
	void			*dst;
	size_t			 srclen;
	size_t			 dstlen;
	size_t			 insize;
	size_t			 outsize;
	size_t			 ret;
	size_t			 room;

	if (!ctx->lz4_recv)
		return 0;

	if (knc_lz4_start_recv(ctx) < 0)
		return -1;

	for (;;) {
		if (ctx->lz4_recv_finished) {
			if (stream_avail(&ctx->sushi_recv) != 0) {
				knc_proto_error(ctx,
				    "LZ4 data after compression end");
				return -1;
			}
			return 0;
		}

		if (stream_avail(&ctx->cooked_recv) >= ctx->recvinbufsiz)
			return 0;
		room = ctx->recvinbufsiz - stream_avail(&ctx->cooked_recv);

		src = NULL;
		srclen = get_ostream(&ctx->sushi_recv, &src,
		    stream_avail(&ctx->sushi_recv));
		if (srclen < 1 && !ctx->lz4_recv_drain_pending) {
			if (ctx->lz4_recv_eof && ctx->lz4_recv_started) {
				knc_proto_error(ctx, "Truncated LZ4 frame");
				return -1;
			}
			return 0;
		}

		dstlen = MIN(KNC_LZ4_OUTPUT_CHUNK, room);
		dst = malloc(dstlen);
		if (!dst) {
			knc_enomem(ctx);
			return -1;
		}

		insize = srclen;
		outsize = dstlen;
		ctx->lz4_recv_drain_pending = 0;
		if (srclen > 0)
			ctx->lz4_recv_started = 1;
		memset(&opts, 0, sizeof(opts));
		ret = LZ4F_decompress(ctx->lz4_recv_ctx, dst, &outsize,
		    src, &insize, &opts);
		if (knc_lz4_error(ctx, ret, "LZ4F_decompress") < 0) {
			free(dst);
			return -1;
		}

		if (insize > 0)
			stream_drain(&ctx->sushi_recv, insize);
		if (ret == 0)
			ctx->lz4_recv_finished = 1;

		if (outsize > 0) {
			if (put_malloc_stream(ctx, &ctx->cooked_recv, dst,
			    outsize) < 0)
				return -1;
		} else
			free(dst);

		if (ret != 0 && outsize == dstlen &&
		    stream_avail(&ctx->sushi_recv) == 0)
			ctx->lz4_recv_drain_pending = 1;

		if (insize == 0 && outsize == 0) {
			if (ctx->lz4_recv_eof && ctx->lz4_recv_started) {
				knc_proto_error(ctx, "Truncated LZ4 frame");
				return -1;
			}
			return 0;
		}

		if (ctx->lz4_recv_finished &&
		    stream_avail(&ctx->sushi_recv) != 0) {
			knc_proto_error(ctx, "LZ4 data after compression end");
			return -1;
		}
	}

	return 0;
}

static void
knc_lz4_mark_recv_eof(knc_ctx ctx)
{

	if (!ctx->lz4_recv)
		return;

	ctx->lz4_recv_eof = 1;
	knc_process_sushi_recv(ctx);
}

static int
knc_raw_command_is(knc_ctx ctx, unsigned char value)
{
	stream_bit	bit;

	bit = ctx->raw_send.cur;
	if (!bit || bit->type != STREAM_COMMAND || bit->len != 1)
		return 0;

	return *(unsigned char *)bit->buf == value;
}

static int
knc_move_raw_command_to_sushi(knc_ctx ctx)
{
	size_t		 len;
	void		*buf;

	if (ctx->lz4_send_started) {
		if (knc_raw_command_is(ctx, 0)) {
			if (knc_lz4_end_send(ctx) < 0)
				return -1;
		} else if (ctx->lz4_flush_pending) {
			if (knc_lz4_flush_send(ctx) < 0)
				return -1;
		}
	}

	buf = knc_get_stream_command(&ctx->raw_send, &len);
	if (put_stream_command(&ctx->sushi_send, buf, len) != len) {
		knc_enomem(ctx);
		return -1;
	}

	return 0;
}

static int
knc_move_raw_data_to_sushi(knc_ctx ctx)
{
	size_t		 len;
	size_t		 wanted;
	void		*buf;

	wanted = ctx->lz4_send ? KNC_LZ4_INPUT_CHUNK : ctx->gssmaxpacket;
	len = get_ostream_contig(&ctx->raw_send, &buf, wanted);

	if (len < 1)
		return 0;

	if (ctx->lz4_send) {
		if (knc_lz4_compress_data(ctx, buf, len) < 0)
			return -1;
	} else {
		if (put_stream(&ctx->sushi_send, buf, len) != len) {
			knc_enomem(ctx);
			return -1;
		}
	}

	stream_drain(&ctx->raw_send, len);
	return 1;
}

static int
knc_move_raw_to_sushi(knc_ctx ctx)
{

	switch (knc_get_stream_bit_type(&ctx->raw_send)) {
	case STREAM_COMMAND:
		return knc_move_raw_command_to_sushi(ctx);
	case STREAM_BUFFER:
		return knc_move_raw_data_to_sushi(ctx);
	default:
		break;
	}

	return 0;
}

static int
knc_state_session(knc_ctx ctx, void *buf, size_t len)
{
	gss_buffer_desc	in;
	gss_buffer_desc	out;
	OM_uint32	maj;
	OM_uint32	min;
	int		conf_state = 0;

	in.value  = buf;
	in.length = len;

	out.length = 0;

	knc_debugf(ctx, "knc_state_session: enter\n");
	maj = gss_unwrap(&min, ctx->gssctx, &in, &out, &conf_state, NULL);

	if (maj != GSS_S_COMPLETE) {
		knc_gss_error(ctx, maj, min, "gss_unwrap");
		return -1;
	}

	if (!(ctx->opts & KNC_OPT_NOPRIVACY) && !conf_state) {
		knc_proto_error(ctx, "gss_unwrap: confidentiality required");
		gss_release_buffer(&min, &out);
		return -1;
	}

	if (out.length == 0) {
		gss_release_buffer(&min, &out);
		if (ctx->opts & KNC_OPT_SENDCMDS)
			ctx->state = STATE_COMMAND;
		else
			knc_remote_read_eof(ctx);
		return 0;
	}

	if (knc_put_unwrapped_data(ctx, &out) < 0) {
		gss_release_buffer(&min, &out);
		return -1;
	}

	return 0;
}

static int
parse_size_t_decimal(const char *buf, size_t len, size_t *ret)
{
	size_t	value;
	size_t	i;
	int	digit;

	if (len == 0)
		return 0;

	value = 0;
	for (i = 0; i < len; i++) {
		if (buf[i] < '0' || buf[i] > '9')
			return 0;
		digit = buf[i] - '0';
		if (value > (SIZE_MAX - digit) / 10)
			return 0;
		value = value * 10 + digit;
	}

	*ret = value;
	return 1;
}

static void
process_capability(knc_ctx ctx, const char *buf, size_t len)
{
	static const char	max_recv_packet[] = "max_recv_packet=";
	size_t			value;
	size_t			keylen;

	keylen = sizeof(max_recv_packet) - 1;
	if (len > keylen && memcmp(buf, max_recv_packet, keylen) == 0) {
		if (!parse_size_t_decimal(buf + keylen, len - keylen, &value))
			return;
		if (value > ctx->peer_max_recv_packet)
			ctx->peer_max_recv_packet = value;
	}
}

/*ARGSUSED*/
static int
cmd_capability(knc_ctx ctx, uint32_t cmdseqno, void *data, size_t len)
{
	const char	*buf;
	const char	*line;
	const char	*end;
	size_t		 linelen;

	if (!data || len == 0)
		return 0;

	buf = data;
	end = buf + len;

	while (buf < end) {
		line = memchr(buf, '\n', end - buf);
		if (line)
			linelen = line - buf;
		else
			linelen = end - buf;

		if (linelen > 0)
			process_capability(ctx, buf, linelen);

		if (!line)
			break;
		buf = line + 1;
	}

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

/*ARGSUSED*/
static int
cmd_compress_lz4(knc_ctx ctx, uint32_t cmdseqno, void *data, size_t len)
{

	if (!(ctx->opts & KNC_OPT_COMPRESS_LZ4)) {
		cmd_unknown(ctx, cmdseqno, data, len);
		return 0;
	}

	knc_put_command(ctx, KNC_CMD_LZ4_ACK, cmdseqno, NULL, 0);
	ctx->lz4_send_pending = 1;
	return 0;
}

/*ARGSUSED*/
static int
cmd_compress_lz4_ok(knc_ctx ctx, uint32_t cmdseqno, void *data, size_t len)
{

	if (ctx->opts & KNC_OPT_COMPRESS_LZ4) {
		ctx->lz4_recv = 1;
		ctx->lz4_recv_started = 0;
		ctx->lz4_recv_finished = 0;
		ctx->lz4_recv_drain_pending = 0;
		ctx->lz4_recv_eof = 0;
		if (knc_lz4_start_recv(ctx) < 0)
			return -1;
	}

	return 0;
}

typedef int (*process_command)(knc_ctx, uint32_t, void *, size_t);

struct {
	const char	*cmd;
	process_command	 f;
} string_cmds[] = {
	{ KNC_CMD_CAPABILITY,	cmd_capability},
	{ "dont_understand",	cmd_dont_understand},
	{ "txt_error",		cmd_txt_error},
	{ KNC_CMD_LZ4_REQUEST,	cmd_compress_lz4},
	{ KNC_CMD_LZ4_ACK,	cmd_compress_lz4_ok},
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

	knc_debugf(ctx, "Received command \"%s\", seq=%u, \"%.*s\", len=%u\n",
	    value, *cmdseqno, (int)*retlen, *retbuf, *retlen);

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
	int		 conf_state = 0;
	int		 ret = 0;

	in.value  = buf;
	in.length = len;

	out.length = 0;

	knc_debugf(ctx, "knc_state_command: enter\n");
	maj = gss_unwrap(&min, ctx->gssctx, &in, &out, &conf_state, NULL);

	if (maj != GSS_S_COMPLETE) {
		knc_gss_error(ctx, maj, min, "gss_unwrap");
		return -1;
	}

	if (!(ctx->opts & KNC_OPT_NOPRIVACY) && !conf_state) {
		knc_proto_error(ctx, "gss_unwrap: confidentiality required");
		gss_release_buffer(&min, &out);
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
		knc_debugf(ctx, "knc_state_command: received dual EOF\n");
		/* XXXrcd: should check if we've sent EOF not if we're open */
		knc_remote_read_eof(ctx);
		knc_remote_write_eof(ctx);
		goto done;
	}

	if (out.length == 1 && *(char *)out.value == 0) {
		knc_debugf(ctx, "knc_state_command: received read EOF\n");
		knc_remote_read_eof(ctx);
		goto done;
	}

	if (out.length == 1 && *(char *)out.value == 1) {
		/* XXXrcd: should check if we've sent EOF not if we're open */
		knc_debugf(ctx, "knc_state_command: received write EOF\n");
		knc_remote_write_eof(ctx);
		goto done;
	}

	cmdbuf    = out.value;
	remainlen = out.length;
	do {
		void	*oldptr = cmdbuf;

		cmdbuflen = remainlen;

		cmd = command_match(ctx, &cmdseqno, &cmdbuf, &cmdbuflen);
		if (!cmd) {
			knc_proto_error(ctx, "Malformed command packet");
			goto done;
		}

		if (cmd(ctx, cmdseqno, cmdbuf, cmdbuflen) < 0) {
			ret = -1;
			goto done;
		}

		cmdbuf    += cmdbuflen;
		remainlen -= (const char *)cmdbuf - (const char *)oldptr;
	} while (remainlen > 0);

done:
	gss_release_buffer(&min, &out);
	return ret;
}

static int
knc_queue_capabilities(knc_ctx ctx)
{
	char	buf[64];
	int	len;

	if (!(ctx->opts & KNC_OPT_SENDCMDS))
		return 0;
	if (ctx->capabilities_sent)
		return 0;

	if (knc_probe_max_recv_packet(ctx) < 0)
		knc_debugf(ctx, "could not probe max_recv_packet\n");

	len = snprintf(buf, sizeof(buf), "max_recv_packet=%zu\n",
	    ctx->local_max_recv_packet);
	if (len < 0 || (size_t)len >= sizeof(buf)) {
		knc_enomem(ctx);
		return -1;
	}

	ctx->capabilities_sent = 1;
	knc_put_command(ctx, KNC_CMD_CAPABILITY, 0, buf, (uint32_t)len);
	return 0;
}

static int
knc_queue_lz4_request(knc_ctx ctx)
{

	if (!(ctx->opts & KNC_OPT_COMPRESS_LZ4))
		return 0;
	if (!(ctx->opts & KNC_OPT_SENDCMDS))
		return 0;
	if (ctx->lz4_request_sent || ctx->lz4_recv)
		return 0;

	ctx->lz4_request_sent = 1;
	knc_put_command(ctx, KNC_CMD_LZ4_REQUEST, 0, NULL, 0);
	return 0;
}

static int
knc_command_is(void *buf, size_t len, const char *cmd)
{
	char		*name;
	char		*end;
	uint32_t	 datalen;
	size_t		 total;
	size_t		 namelen;

	if (len < sizeof(uint32_t) + 1 + sizeof(uint32_t))
		return 0;

	name = (char *)buf + sizeof(uint32_t);
	end = memchr(name, 0, len - sizeof(uint32_t));
	if (!end)
		return 0;
	namelen = end - name;
	total = sizeof(uint32_t) + namelen + 1 + sizeof(uint32_t);
	if (total > len)
		return 0;
	if (strcmp(name, cmd))
		return 0;

	memcpy(&datalen, name + namelen + 1, sizeof(datalen));
	datalen = ntohl(datalen);
	if (datalen > len - total || total + datalen != len)
		return 0;

	return 1;
}

static void
knc_maybe_enable_lz4_send(knc_ctx ctx, void *buf, size_t len)
{

	if (!ctx->lz4_send_pending)
		return;
	if (!knc_command_is(buf, len, KNC_CMD_LZ4_ACK))
		return;

	ctx->lz4_send_pending = 0;
	ctx->lz4_send = 1;
	ctx->lz4_send_started = 0;
	ctx->lz4_send_ended = 0;
	ctx->lz4_flush_pending = 0;
}

static void
knc_discard_empty_input(knc_ctx ctx, int dir)
{
	stream	s;

	if (dir == KNC_DIR_SEND)
		s = &ctx->raw_send;
	else
		s = &ctx->raw_recv;

	if (s && s->cur && s->cur->len == 0)
		stream_drain(s, 0);
}

static void
knc_remote_read_eof(knc_ctx ctx)
{
	knc_lz4_mark_recv_eof(ctx);

	ctx->open &= ~OPEN_READ;

	if ((ctx->opts & KNC_OPT_NO_HALF_CLOSE) && (ctx->open & OPEN_WRITE))
		knc_put_eof(ctx, KNC_DIR_SEND);

	knc_maybe_shutdown_fds(ctx);
}

static void
knc_remote_write_eof(knc_ctx ctx)
{

	if (ctx->open & OPEN_WRITE)
		knc_put_eof(ctx, KNC_DIR_SEND);

	ctx->open &= ~OPEN_WRITE;

	if (ctx->opts & KNC_OPT_NO_HALF_CLOSE)
		ctx->open &= ~OPEN_READ;

	knc_maybe_shutdown_fds(ctx);
}

static void
knc_local_read_eof(knc_ctx ctx)
{

	if (ctx->open & OPEN_WRITE)
		knc_put_eof(ctx, KNC_DIR_SEND);

	if ((ctx->opts & KNC_OPT_NO_HALF_CLOSE) && (ctx->open & OPEN_READ)) {
		knc_put_eof(ctx, KNC_DIR_RECV);
		ctx->open &= ~OPEN_READ;
	}

	knc_maybe_shutdown_fds(ctx);
}

static void
knc_local_write_eof(knc_ctx ctx)
{

	if (ctx->open & OPEN_READ) {
		knc_put_eof(ctx, KNC_DIR_RECV);
		ctx->open &= ~OPEN_READ;
	}

	if ((ctx->opts & KNC_OPT_NO_HALF_CLOSE) && (ctx->open & OPEN_WRITE))
		knc_put_eof(ctx, KNC_DIR_SEND);

	knc_maybe_shutdown_fds(ctx);
}

static void
knc_network_read_eof(knc_ctx ctx)
{
	knc_lz4_mark_recv_eof(ctx);

	ctx->open &= ~OPEN_READ;

	if ((ctx->opts & KNC_OPT_NO_HALF_CLOSE) && (ctx->open & OPEN_WRITE))
		knc_put_eof(ctx, KNC_DIR_SEND);

	knc_maybe_shutdown_fds(ctx);
}

static void
knc_network_write_eof(knc_ctx ctx)
{

	ctx->open &= ~OPEN_WRITE;

	if (ctx->opts & KNC_OPT_NO_HALF_CLOSE)
		ctx->open &= ~OPEN_READ;

	knc_maybe_shutdown_fds(ctx);
}

static int
knc_state_process_in(knc_ctx ctx)
{
	void	*buf;
	size_t	 len;
	int	 ret;

	knc_debugf(ctx, "knc_state_process_in: enter\n");

	/*
	 * We have two main flows in which we are interested, input
	 * and output.  So, we check to see what is on each queue and
	 * if we can make progress.
	 *
	 * First we process the read side.  Let's see if we have a
	 * packet.
	 */

	for (;;) {
		if (ctx->error)
			return -1;

		len = read_packet(ctx, &ctx->raw_recv, &buf);

		knc_debugf(ctx, "read_packet returned %zd\n", len);

		if (ctx->error)
			return -1;

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

		if (ret < 0 || ctx->error)
			return -1;

		/* XXXrcd: EOF handling likely wants to go here. */

	}

	/*NOTREACHED*/
	return ret;
}

static int
knc_state_process_out(knc_ctx ctx)
{
	int		 rawtype;
	int		 ret;

	knc_debugf(ctx, "knc_state_process_out: enter\n");

	/*
	 * We only process our out buffer if we have established the
	 * GSSAPI connexion because the handshake routines write directly
	 * to ctx->cooked_send.
	 */

	if (ctx->state != STATE_SESSION && ctx->state != STATE_COMMAND)
		return 0;

	if (knc_queue_capabilities(ctx) < 0)
		return -1;
	knc_queue_lz4_request(ctx);

	while (stream_avail(&ctx->cooked_send) < ctx->sendmax) {
		if (knc_get_stream_bit_type(&ctx->sushi_send)) {
			ret = wrap_sushi_packet(ctx);
			if (ret < 0)
				return -1;
			if (ret == 0)
				return 0;
			continue;
		}

		rawtype = knc_get_stream_bit_type(&ctx->raw_send);
		if (rawtype) {
			if (knc_move_raw_to_sushi(ctx) < 0)
				return -1;
			continue;
		}

		if (ctx->lz4_flush_pending) {
			if (knc_lz4_flush_send(ctx) < 0)
				return -1;
			continue;
		}

		return 0;

	}

	knc_debugf(ctx, "knc_state_process_out: leave\n");

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
		knc_debugf(ctx, "putting command: send EOF\n");
		buf[0] = 0;
		ctx->open &= ~OPEN_WRITE;
	} else {
		knc_debugf(ctx, "putting command: recv EOF\n");
		buf[0] = 1;
	}

	if (!(ctx->opts & KNC_OPT_SENDCMDS))
		return 0;

	put_stream_command(&ctx->raw_send, buf, 1);
	return 0;
}

int
knc_put_command(knc_ctx ctx, const char *cmd, uint32_t cmdseqno,
		const void *data, uint32_t datalen)
{
	char	*buf;
	char	*tmp;
	size_t	 cmdlen;
	size_t	 len = 0;
	size_t	 tlen = 0;
	size_t	 ret;

	if (!ctx || !cmd || (datalen > 0 && !data))
		return 0;

	if (!(ctx->opts & KNC_OPT_SENDCMDS))
		return 0;

	cmdlen = strlen(cmd) + 1;
	if (cmdlen > SIZE_MAX - sizeof(cmdseqno) - sizeof(datalen) - datalen)
		return 0;

	len = sizeof(cmdseqno) + cmdlen + sizeof(datalen) + datalen;
	tmp = buf = malloc(len);
	if (!buf)
		return 0;

	cmdseqno = htonl(cmdseqno);
	memcpy(tmp, &cmdseqno, sizeof(cmdseqno));

	tmp += sizeof(cmdseqno);
	tlen += sizeof(cmdseqno);

	memcpy(tmp, cmd, cmdlen);

	tmp += cmdlen;
	tlen += cmdlen;

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

	knc_debugf(ctx, "putting command: %s seq=%u\n", cmd, cmdseqno);

	ret = put_stream_command(&ctx->raw_send, buf, len);
	free(buf);
	return ret;
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

	if (dir == KNC_DIR_SEND) {
		ret += stream_avail(&ctx->sushi_send);
		if (ctx->lz4_flush_pending)
			ret++;
	} else {
		ret += stream_avail(&ctx->sushi_recv);
		if (ctx->lz4_recv_drain_pending)
			ret++;
	}

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
	knc_debugf(ctx, "going to get tickets for: %s\n", (char *)name.value);
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
	int	fdflags;
	int	statusflags;

	statusflags = fcntl(s, F_GETFL, 0);
	if (statusflags < 0)
		return -1;

	statusflags &= ~O_NONBLOCK;

	if (opts & KNC_SOCK_NONBLOCK)
		statusflags |= O_NONBLOCK;

#ifdef O_NOSIGPIPE
	statusflags |= O_NOSIGPIPE;
#endif

	if (fcntl(s, F_SETFL, statusflags) < 0)
		return -1;

	fdflags = fcntl(s, F_GETFD, 0);
	if (fdflags < 0)
		return -1;
	if (opts & KNC_SOCK_CLOEXEC)
		fdflags |= FD_CLOEXEC;
	else
		fdflags &= ~FD_CLOEXEC;

	return fcntl(s, F_SETFD, fdflags);
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
	if (s >= 0 && socket_options(s, opts) < 0) {
		close(s);
		return -1;
	}

	return s;
}

static int
connect_host(knc_ctx ctx, const char *domain, const char *service, int flags)
{
	struct	addrinfo ai, *res, *res0;
	int	ret;
	int	s = -1;

	knc_debugf(ctx, "connecting to (%s, %s)...\n", service, domain);

	memset(&ai, 0x0, sizeof(ai));
	ai.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(domain, service, &ai, &res0);
	if (ret) {
		knc_generic_error(ctx, KNC_ERROR_GENERIC,
		    "getaddrinfo: (%s,%s) %s", domain,
		    service, gai_strerror(ret));
		return -1;
	}

	for (res=res0; res; res=res->ai_next) {
		s = get_socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol, flags);
		if (s == -1) {
			knc_debugf(ctx, "connect: %s\n", strerror(errno));
			continue;
		}
		ret = connect(s, res->ai_addr, res->ai_addrlen);
		if (ret != -1)
			break;
		close(s);
		s = -1;
		knc_debugf(ctx, "connect: %s\n", strerror(errno));
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
	stream_garbage_collect(&ctx->sushi_recv);
	stream_garbage_collect(&ctx->raw_send);
	stream_garbage_collect(&ctx->sushi_send);
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
	struct timespec	ts_zero = {0, 0};
	sigset_t	blocked;
	sigset_t	pending;
	sigset_t	sigpipe_mask;
	ssize_t		ret;
	int		fd = ((struct fd_cookie *)cookie)->wfd;
	int		my_errno;

	/*
	 * We must do a bit of a dance to avoid allowing a SIGPIPE to be
	 * delivered outside our control.  Basically, check to see if there's
	 * one pending, if not block SIGPIPE, do the writev(2), consume any
	 * generated SIGPIPE, and restore the old sigmask.
         *
         * pthread_sigmask() is thread-safe, but sigismember() and
         * sigtimedwait() are not.  We might end up consuming a SIGPIPE
         * we shouldn't consume.
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

	if (wfd != -1 && rfd != wfd)
		close(wfd);

	if (rfd != -1)
		return close(rfd);

	return 0;
}

static int
fd_shutdown_or_close(struct fd_cookie *fdc, int how)
{
	int	fd;
	int	ret;

	if (!fdc)
		return 0;

	switch (how) {
	case SHUT_RD:
		if (fdc->rclosed || fdc->rfd == -1)
			return 0;
		fd = fdc->rfd;
		ret = shutdown(fd, SHUT_RD);
		fdc->rclosed = 1;
		if (ret == -1) {
			ret = close(fd);
			if (fdc->wfd == fd) {
				fdc->wfd = -1;
				fdc->wclosed = 1;
			}
			fdc->rfd = -1;
		}
		return ret;
	case SHUT_WR:
		if (fdc->wclosed || fdc->wfd == -1)
			return 0;
		fd = fdc->wfd;
		ret = shutdown(fd, SHUT_WR);
		fdc->wclosed = 1;
		if (ret == -1) {
			ret = close(fd);
			if (fdc->rfd == fd) {
				fdc->rfd = -1;
				fdc->rclosed = 1;
			}
			fdc->wfd = -1;
		}
		return ret;
	case SHUT_RDWR:
		ret = fd_shutdown_or_close(fdc, SHUT_RD);
		if (fd_shutdown_or_close(fdc, SHUT_WR) == -1)
			ret = -1;
		return ret;
	default:
		errno = EINVAL;
		return -1;
	}
}

static int
fd_cookie_readable(struct fd_cookie *fdc)
{

	return fdc && fdc->rfd != -1 && !fdc->rclosed;
}

static int
fd_cookie_writable(struct fd_cookie *fdc)
{

	return fdc && fdc->wfd != -1 && !fdc->wclosed;
}

static void
knc_maybe_shutdown_fds(knc_ctx ctx)
{

	if (!ctx)
		return;

	if (!(ctx->open & OPEN_READ) && knc_pending(ctx, KNC_DIR_RECV) == 0) {
		if (ctx->net_uses_fd)
			fd_shutdown_or_close(ctx->netcookie, SHUT_RD);
		if (ctx->local_uses_fd)
			fd_shutdown_or_close(ctx->localcookie, SHUT_WR);
	}

	if (!(ctx->open & OPEN_WRITE) && knc_pending(ctx, KNC_DIR_SEND) == 0) {
		if (ctx->net_uses_fd)
			fd_shutdown_or_close(ctx->netcookie, SHUT_WR);
		if (ctx->local_uses_fd)
			fd_shutdown_or_close(ctx->localcookie, SHUT_RD);
	}
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

	cookie->mine    = 0;
	cookie->rfd     = rfd;
	cookie->wfd     = wfd;
	cookie->rclosed = 0;
	cookie->wclosed = 0;

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

	if (ctx && ctx->net_uses_fd) {
		if (fd_cookie_readable(ctx->netcookie))
			return ((struct fd_cookie *)ctx->netcookie)->rfd;
	}

	return -1;
}

int
knc_get_net_wfd(knc_ctx ctx)
{

	if (ctx && ctx->net_uses_fd) {
		if (fd_cookie_writable(ctx->netcookie))
			return ((struct fd_cookie *)ctx->netcookie)->wfd;
	}

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

	cookie->mine    = 0;
	cookie->rfd     = rfd;
	cookie->wfd     = wfd;
	cookie->rclosed = 0;
	cookie->wclosed = 0;

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

	if (ctx && ctx->local_uses_fd) {
		if (fd_cookie_readable(ctx->localcookie))
			return ((struct fd_cookie *)ctx->localcookie)->rfd;
	}

	return -1;
}

int
knc_get_local_wfd(knc_ctx ctx)
{

	if (ctx && ctx->local_uses_fd) {
		if (fd_cookie_writable(ctx->localcookie))
			return ((struct fd_cookie *)ctx->localcookie)->wfd;
	}

	return -1;
}

int
knc_need_input(knc_ctx ctx, int dir)
{

	if (!ctx)
		return 0;

	if (dir == KNC_DIR_RECV && !(ctx->open & OPEN_READ))
		return 0;

	if (dir == KNC_DIR_SEND && !(ctx->open & OPEN_WRITE))
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
	int	fd;

	if (!ctx)
		return 0;
	if (!fds || !cbs)
		return (nfds_t)-1;

	fd = knc_get_net_rfd(ctx);
	if (fd >= 0 && knc_need_input(ctx, KNC_DIR_RECV)) {
		if (i >= nfds)
			return (nfds_t)-1;
		cbs[i]		= _fill_recv;
		fds[i].fd	= fd;
		fds[i++].events	= POLLIN;
	}

	fd = knc_get_net_wfd(ctx);
	if (fd >= 0 && knc_can_output(ctx, KNC_DIR_SEND)) {
		if (i >= nfds)
			return (nfds_t)-1;
		cbs[i]		= _flush_send;
		fds[i].fd	= fd;
		fds[i++].events = POLLOUT;
	}

	if (knc_is_authenticated(ctx)) {
		fd = knc_get_local_rfd(ctx);
		if (fd >= 0 && knc_need_input(ctx, KNC_DIR_SEND)) {
		/*
		 * Here, we are reading unframed bytes and so we size our
		 * buffer as the slightly more accurate raw+cooked size for
		 * comparison.
		 */
			if (i >= nfds)
				return (nfds_t)-1;
			cbs[i]		= _fill_send;
			fds[i].fd	 = fd;
			fds[i++].events	 = POLLIN;
		}

		fd = knc_get_local_wfd(ctx);
		if (fd >= 0 && knc_can_output(ctx, KNC_DIR_RECV)) {
			if (i >= nfds)
				return (nfds_t)-1;
			cbs[i]		= _flush_recv;
			fds[i].fd	 = fd;
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

		if (revents & (POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL))
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

	if (ctx->service == GSS_C_NO_NAME)
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
	size_t	  wanted;
	void	 *tmpbuf;
	ssize_t	(*ourread)(void *, void *, size_t);
	void	 *ourcookie;
	ssize_t	  ret;

	if (!ctx || ctx->error)
		return EIO;

	if (dir == KNC_DIR_SEND) {
		ourread   =  ctx->localread;
		ourcookie =  ctx->localcookie;
		wanted	  =  MIN(ctx->gssmaxpacket, ctx->sendinbufsiz);
	} else {
		ourread   = ctx->netread;
		ourcookie = ctx->netcookie;
		wanted	  = ctx->recvinbufsiz;
	}

	/* XXXrcd: deal properly with EOF */
	/* XXXrcd: looping? */
	/* XXXrcd: hmmm! */

	if (!ourread || !ourcookie)
		return EINVAL;

	len = knc_get_ibuf(ctx, dir, &tmpbuf, wanted);
	if (!len) {
		knc_enomem(ctx);
		return ENOMEM;
	}

	knc_debugf(ctx, "knc_fill: about to read %zd bytes.\n", len);

	ret = ourread(ourcookie, tmpbuf, (size_t)len);

	if (ret == -1) {
		knc_debugf(ctx, "read error: %s\n", strerror(errno));
		return errno_switch(ctx, errno, "reading");
	}

	if (ret == 0) {
		knc_debugf(ctx, "knc_fill: got EOF\n");
		knc_discard_empty_input(ctx, dir);

		if (dir == KNC_DIR_SEND) {
			knc_local_read_eof(ctx);
			knc_garbage_collect(ctx);
			return 0;
		}

		if ((ctx->state == STATE_SESSION ||
		     ctx->state == STATE_COMMAND) &&
		    stream_avail(&ctx->raw_recv) == 0) {
			knc_network_read_eof(ctx);
			knc_garbage_collect(ctx);
			return 0;
		}

		/*
		 * XXXrcd: we may very well call this an error because
		 *         we are supposed to see an appropriate command
		 *         packet for close.
		 */
		if (ctx->open & OPEN_READ) {
			knc_proto_error(ctx, "Short input");
			knc_garbage_collect(ctx);
			return EIO;
		}

		return 0;
	}

	if (ret > 0) {
		knc_debugf(ctx, "Read %zd bytes\n", ret);
		knc_fill_buf(ctx, dir, (size_t)ret);
	}

	if (dir == KNC_DIR_RECV && knc_state_process_in(ctx) < 0) {
		knc_garbage_collect(ctx);
		return EIO;
	}

	knc_maybe_shutdown_fds(ctx);
	knc_garbage_collect(ctx);

	if (ctx->error)
		return EIO;

	return 0;
}

int
knc_flush(knc_ctx ctx, int dir, size_t flushlen)
{
	struct iovec	 *vec;
	int		  iovcnt;
	size_t		  completelen = 0;
	size_t		  outlen;
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
		if (dir == KNC_DIR_SEND) {
			if (knc_state_process_out(ctx) < 0)
				return EIO;
		} else if (knc_process_sushi_recv(ctx) < 0)
			return EIO;

		len = knc_get_obufv(ctx, dir, MAX_IOVCNT, &vec, &iovcnt);
		if (len <= 0)
			break;
		outlen = (size_t)len;
		knc_debugf(ctx, "knc_flush: about to write %zu bytes.\n",
		    outlen);

		len = ourwritev(ourcookie, vec, iovcnt);

		if (len == -1) {
			knc_debugf(ctx, "write error: %s\n", strerror(errno));
			if (errno == EPIPE) {
				knc_drain_buf(ctx, dir, outlen);
				if (dir == KNC_DIR_RECV)
					knc_local_write_eof(ctx);
				else
					knc_network_write_eof(ctx);
				knc_garbage_collect(ctx);
				return 0;
			}
			return errno_switch(ctx, errno, "writev");
		}

		*total += len;
		knc_debugf(ctx, "knc_flush: wrote %zd bytes, total=%zd\n",
		    len, *total);
		knc_drain_buf(ctx, dir, (size_t)len);

		knc_garbage_collect(ctx);

		completelen += len;
		if (completelen >= flushlen)
			break;
	}

	knc_maybe_shutdown_fds(ctx);
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

	knc_maybe_shutdown_fds(ctx);

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

char *
knc_gss_errstring(OM_uint32 maj_stat, OM_uint32 min_stat, const char *preamble)
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

#define GENERIC_BUFSIZ	1024

void
knc_generic_error(knc_ctx ctx, int errtype, const char *fmt, ...)
{
	va_list ap;

	ctx->error  = errtype;
	ctx->errstr = malloc(GENERIC_BUFSIZ);

	if (!ctx->errstr)
		return;

	va_start(ap, fmt);
	vsnprintf(ctx->errstr, GENERIC_BUFSIZ, fmt, ap);
	va_end(ap);
}

void
knc_proto_error(knc_ctx ctx, const char *fmt, ...)
{
	va_list ap;

	ctx->error  = KNC_ERROR_PROTO;
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
	ctx->errstr = knc_gss_errstring(maj_stat, min_stat, s);
	if (!ctx->errstr)
		ctx->errstr = strdup("Failed to construct GSS error");
	knc_debugf(ctx, "knc_gss_error: %s\n", ctx->errstr);
}

void
knc_enomem(knc_ctx ctx)
{

	knc_syscall_error(ctx, "Out of memory", ENOMEM);
}
