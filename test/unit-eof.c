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

#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
check_no_error(knc_ctx ctx, const char *message)
{

	if (knc_error(ctx)) {
		fprintf(stderr, "%s: %s\n", message, knc_errstr(ctx));
		exit(1);
	}
}

static void
test_no_half_close_option(void)
{
	knc_ctx	ctx;

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	check(!knc_get_opt(ctx, KNC_OPT_NO_HALF_CLOSE),
	    "KNC_OPT_NO_HALF_CLOSE defaulted to enabled");

	knc_set_opt(ctx, KNC_OPT_NO_HALF_CLOSE, 1);
	check(knc_get_opt(ctx, KNC_OPT_NO_HALF_CLOSE),
	    "KNC_OPT_NO_HALF_CLOSE did not enable");

	knc_set_opt(ctx, KNC_OPT_NO_HALF_CLOSE, 0);
	check(!knc_get_opt(ctx, KNC_OPT_NO_HALF_CLOSE),
	    "KNC_OPT_NO_HALF_CLOSE did not disable");

	knc_ctx_destroy(ctx);
}

static void
test_local_read_eof_queues_send_eof(void)
{
	knc_ctx	ctx;
	int	fds[2];
	int	ret;

	check(pipe(fds) == 0, "pipe failed");
	close(fds[1]);

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	knc_set_local_fds(ctx, fds[0], -1);

	ret = knc_fill(ctx, KNC_DIR_SEND);
	check(ret == 0, "local read EOF returned an error");
	check_no_error(ctx, "local read EOF set an error");
	check(!(ctx->open & OPEN_WRITE), "local read EOF left write side open");
	check(ctx->open & OPEN_READ, "local read EOF closed read side");
	check(knc_pending(ctx, KNC_DIR_SEND) == 1,
	    "local read EOF did not queue exactly one EOF command");

	close(fds[0]);
	knc_ctx_destroy(ctx);
}

static void
test_no_half_close_local_read_eof_closes_both_sides(void)
{
	knc_ctx	ctx;
	int	fds[2];
	int	ret;

	check(pipe(fds) == 0, "pipe failed");
	close(fds[1]);

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	knc_set_opt(ctx, KNC_OPT_NO_HALF_CLOSE, 1);
	knc_set_local_fds(ctx, fds[0], -1);

	ret = knc_fill(ctx, KNC_DIR_SEND);
	check(ret == 0, "no-half-close local read EOF returned an error");
	check_no_error(ctx, "no-half-close local read EOF set an error");
	check(ctx->open == 0, "no-half-close local read EOF left a side open");
	check(knc_pending(ctx, KNC_DIR_SEND) == 2,
	    "no-half-close local read EOF did not queue both EOF commands");

	close(fds[0]);
	knc_ctx_destroy(ctx);
}

static void
test_network_eof_after_authentication_is_eof(void)
{
	knc_ctx	ctx;
	int	fds[2];
	int	ret;

	check(pipe(fds) == 0, "pipe failed");
	close(fds[1]);

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	ctx->state = STATE_SESSION;
	knc_set_net_fds(ctx, fds[0], -1);

	ret = knc_fill(ctx, KNC_DIR_RECV);
	check(ret == 0, "network EOF returned an error");
	check_no_error(ctx, "network EOF set an error");
	check(!(ctx->open & OPEN_READ), "network EOF left read side open");
	check(!knc_need_input(ctx, KNC_DIR_RECV),
	    "network EOF still wanted network input");

	close(fds[0]);
	knc_ctx_destroy(ctx);
}

static void
test_network_mid_packet_eof_is_protocol_error(void)
{
	knc_ctx	ctx;
	char	buf = 0;
	int	fds[2];
	int	ret;

	check(pipe(fds) == 0, "pipe failed");
	check(write(fds[1], &buf, sizeof(buf)) == sizeof(buf),
	    "write failed");
	close(fds[1]);

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	ctx->state = STATE_SESSION;
	knc_set_net_fds(ctx, fds[0], -1);

	ret = knc_fill(ctx, KNC_DIR_RECV);
	check(ret == 0, "partial network packet read returned an error");
	check_no_error(ctx, "partial network packet read set an error");
	check(stream_avail(&ctx->raw_recv) == 1,
	    "partial network packet was not buffered");

	ret = knc_fill(ctx, KNC_DIR_RECV);
	check(ret == EIO, "mid-packet network EOF was not an I/O error");
	check(knc_error(ctx) == KNC_ERROR_PROTO,
	    "mid-packet network EOF was not a protocol error");

	close(fds[0]);
	knc_ctx_destroy(ctx);
}

static void
test_local_write_epipe_queues_receive_eof(void)
{
	knc_ctx	ctx;
	int	fds[2];
	int	ret;

	check(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0,
	    "socketpair failed");
	close(fds[1]);

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	ctx->state = STATE_SESSION;
	knc_set_local_fds(ctx, -1, fds[0]);
	put_stream(&ctx->cooked_recv, "x", 1);

	ret = knc_flush(ctx, KNC_DIR_RECV, 0);
	check(ret == 0, "local write EPIPE returned an error");
	check_no_error(ctx, "local write EPIPE set an error");
	check(!(ctx->open & OPEN_READ),
	    "local write EPIPE left read side open");
	check(ctx->open & OPEN_WRITE,
	    "local write EPIPE closed write side");
	check(knc_pending(ctx, KNC_DIR_RECV) == 0,
	    "local write EPIPE left receive data pending");
	check(knc_pending(ctx, KNC_DIR_SEND) == 1,
	    "local write EPIPE did not queue receive EOF command");

	close(fds[0]);
	knc_ctx_destroy(ctx);
}

static void
test_network_write_epipe_closes_write_side(void)
{
	knc_ctx	ctx;
	int	fds[2];
	int	ret;

	check(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0,
	    "socketpair failed");
	close(fds[1]);

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	ctx->state = STATE_SESSION;
	knc_set_net_fds(ctx, -1, fds[0]);
	put_stream(&ctx->cooked_send, "x", 1);

	ret = knc_flush(ctx, KNC_DIR_SEND, 0);
	check(ret == 0, "network write EPIPE returned an error");
	check_no_error(ctx, "network write EPIPE set an error");
	check(ctx->open & OPEN_READ,
	    "network write EPIPE closed read side");
	check(!(ctx->open & OPEN_WRITE),
	    "network write EPIPE left write side open");
	check(knc_pending(ctx, KNC_DIR_SEND) == 0,
	    "network write EPIPE left send data pending");

	close(fds[0]);
	knc_ctx_destroy(ctx);
}

int
main(void)
{

	test_no_half_close_option();
	test_local_read_eof_queues_send_eof();
	test_no_half_close_local_read_eof_closes_both_sides();
	test_network_eof_after_authentication_is_eof();
	test_network_mid_packet_eof_is_protocol_error();
	test_local_write_epipe_queues_receive_eof();
	test_network_write_epipe_closes_write_side();

	return 0;
}
