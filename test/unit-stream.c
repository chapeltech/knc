/* */

/*-
 * Copyright 2026 Roland C. Dowdeswell
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/libknc.c"

static void
check(int condition, const char *message)
{

	if (!condition) {
		fprintf(stderr, "%s\n", message);
		exit(1);
	}
}

static void
test_input_reuses_only_reachable_tail_space(void)
{
	char	first[16 * 1024];
	char	second[16 * 1024];
	void	*buf;
	size_t	len;
	knc_ctx	ctx;

	memset(first, 'a', sizeof(first));
	memset(second, 'b', sizeof(second));

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");

	check(put_stream(&ctx->raw_send, first, sizeof(first)) ==
	    sizeof(first), "first put_stream failed");
	len = get_ostream_contig(&ctx->raw_send, &buf, sizeof(first));
	check(len == sizeof(first), "first stream bit was not readable");
	check(memcmp(buf, first, sizeof(first)) == 0,
	    "first stream bit content mismatch");
	check(stream_drain(&ctx->raw_send, sizeof(first)) ==
	    (ssize_t)sizeof(first), "first stream drain failed");
	check(stream_avail(&ctx->raw_send) == 0,
	    "drained stream still had available bytes");

	check(put_stream(&ctx->raw_send, second, sizeof(second)) ==
	    sizeof(second), "second put_stream failed");
	len = get_ostream_contig(&ctx->raw_send, &buf, sizeof(second));
	check(len == sizeof(second),
	    "second stream bit was not reachable after drain");
	check(memcmp(buf, second, sizeof(second)) == 0,
	    "second stream bit content mismatch");

	knc_ctx_destroy(ctx);
}

static void
test_input_reuses_partial_tail_after_short_fill(void)
{
	void		*first;
	void		*second;
	stream_bit	 tail;
	size_t		len;
	knc_ctx		ctx;

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");

	len = get_istream(&ctx->raw_send, &first, STREAM_BIT_ALLOC_UNIT);
	check(len == STREAM_BIT_ALLOC_UNIT,
	    "initial input reservation had the wrong size");
	check(stream_fill(&ctx->raw_send, 1) == 1,
	    "short input fill failed");
	tail = ctx->raw_send.tail;

	len = get_istream(&ctx->raw_send, &second, STREAM_BIT_ALLOC_UNIT);
	check(len == STREAM_BIT_ALLOC_UNIT - 1,
	    "partial input tail did not limit the next reservation");
	check(ctx->raw_send.tail == tail,
	    "short input fill allocated a new stream bit");
	check(second == (char *)first + 1,
	    "short input fill did not reuse adjacent tail space");

	knc_ctx_destroy(ctx);
}

static void
test_fill_reports_state_handler_failure(void)
{
	uint32_t	wirelen;
	unsigned char	frame[5];
	knc_ctx		ctx;
	int		fds[2];

	check(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0,
	    "socketpair failed");
	wirelen = htonl(1);
	memcpy(frame, &wirelen, sizeof(wirelen));
	frame[4] = 0;
	check(write(fds[1], frame, sizeof(frame)) == (ssize_t)sizeof(frame),
	    "frame write failed");

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	knc_set_net_fd(ctx, fds[0]);
	check(knc_fill(ctx, KNC_DIR_RECV) == EIO,
	    "knc_fill ignored a state handler failure");

	knc_ctx_destroy(ctx);
	close(fds[0]);
	close(fds[1]);
}

static void
test_cloexec_uses_descriptor_flags(void)
{
	knc_ctx	ctx;
	int	fds[2];

	check(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0,
	    "socketpair failed");
	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	knc_set_net_fds(ctx, fds[0], fds[1]);

	knc_set_opt(ctx, KNC_SOCK_CLOEXEC, 1);
	check((fcntl(fds[0], F_GETFD) & FD_CLOEXEC) != 0,
	    "CLOEXEC was not set on the read descriptor");
	check((fcntl(fds[1], F_GETFD) & FD_CLOEXEC) != 0,
	    "CLOEXEC was not set on the write descriptor");

	knc_set_opt(ctx, KNC_SOCK_CLOEXEC, 0);
	check((fcntl(fds[0], F_GETFD) & FD_CLOEXEC) == 0,
	    "CLOEXEC was not cleared on the read descriptor");
	check((fcntl(fds[1], F_GETFD) & FD_CLOEXEC) == 0,
	    "CLOEXEC was not cleared on the write descriptor");

	knc_ctx_destroy(ctx);
	close(fds[0]);
	close(fds[1]);
}

static void
test_ostreamv_honours_vector_limit(void)
{
	char		 first[STREAM_BIT_ALLOC_UNIT];
	char		 second[STREAM_BIT_ALLOC_UNIT];
	struct iovec	*vec;
	knc_ctx		 ctx;
	size_t		 len;
	int		 count;

	memset(first, 'a', sizeof(first));
	memset(second, 'b', sizeof(second));
	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	check(put_stream(&ctx->cooked_recv, first, sizeof(first)) ==
	    sizeof(first), "first put_stream failed");
	check(put_stream(&ctx->cooked_recv, second, sizeof(second)) ==
	    sizeof(second), "second put_stream failed");

	len = get_ostreamv(&ctx->cooked_recv, 1, &vec, &count);
	check(count == 1, "get_ostreamv exceeded maxcnt");
	check(len == STREAM_BIT_ALLOC_UNIT,
	    "get_ostreamv returned bytes beyond maxcnt");
	check(vec[0].iov_len == STREAM_BIT_ALLOC_UNIT,
	    "get_ostreamv returned the wrong first vector length");
	knc_garbage_collect(ctx);

	knc_ctx_destroy(ctx);
}

static void
test_pollfds_accepts_fd_zero_and_exact_capacity(void)
{
	knc_callback	cbs[1];
	struct pollfd	pollfds[1];
	knc_ctx		ctx;
	nfds_t		count;
	int		fds[2];
	int		saved_stdin;

	saved_stdin = dup(STDIN_FILENO);
	close(STDIN_FILENO);
	check(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0,
	    "socketpair failed");
	check(fds[0] == STDIN_FILENO, "socketpair did not allocate fd zero");

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	knc_set_net_fd(ctx, fds[0]);
	count = knc_get_pollfds(ctx, pollfds, cbs, 1);
	check(count == 1, "exact pollfd capacity was rejected");
	check(pollfds[0].fd == STDIN_FILENO,
	    "file descriptor zero was omitted from pollfds");

	pollfds[0].fd = 123;
	count = knc_get_pollfds(ctx, pollfds, cbs, 0);
	check(count == (nfds_t)-1, "zero pollfd capacity was accepted");
	check(pollfds[0].fd == 123, "pollfds was written beyond capacity");

	knc_ctx_destroy(ctx);
	close(fds[0]);
	close(fds[1]);
	if (saved_stdin >= 0) {
		check(dup2(saved_stdin, STDIN_FILENO) == STDIN_FILENO,
		    "failed to restore stdin");
		close(saved_stdin);
	}
}

static void
test_large_command_uses_exact_storage(void)
{
	const char	 command[] = "large-test";
	unsigned char	*data;
	unsigned char	*wire;
	knc_ctx		 ctx;
	size_t		 expected;
	size_t		 len;
	size_t		 ret;
	uint32_t	 datalen = 3 * STREAM_BIT_ALLOC_UNIT;

	data = malloc(datalen);
	check(data != NULL, "large command data allocation failed");
	memset(data, 0x5a, datalen);
	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");

	expected = sizeof(uint32_t) + sizeof(command) + sizeof(uint32_t) +
	    datalen;
	ret = knc_put_command(ctx, command, 7, data, datalen);
	check(ret == expected, "large command was not queued completely");
	wire = knc_get_stream_command(&ctx->raw_send, &len);
	check(wire != NULL && len == expected,
	    "large command storage length was truncated");
	check(memcmp(wire + sizeof(uint32_t), command, sizeof(command)) == 0,
	    "large command name was corrupted");
	check(wire[len - 1] == 0x5a, "large command data was truncated");

	knc_ctx_destroy(ctx);
	free(data);
}

int
main(void)
{

	test_input_reuses_only_reachable_tail_space();
	test_input_reuses_partial_tail_after_short_fill();
	test_fill_reports_state_handler_failure();
	test_cloexec_uses_descriptor_flags();
	test_ostreamv_honours_vector_limit();
	test_pollfds_accepts_fd_zero_and_exact_capacity();
	test_large_command_uses_exact_storage();

	return 0;
}
