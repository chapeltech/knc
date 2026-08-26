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
	check(!knc_get_opt(ctx, KNC_OPT_SENDCMDS),
	    "KNC_OPT_SENDCMDS defaulted to enabled");

	knc_set_opt(ctx, KNC_OPT_NO_HALF_CLOSE, 1);
	check(knc_get_opt(ctx, KNC_OPT_NO_HALF_CLOSE),
	    "KNC_OPT_NO_HALF_CLOSE did not enable");

	knc_set_opt(ctx, KNC_OPT_NO_HALF_CLOSE, 0);
	check(!knc_get_opt(ctx, KNC_OPT_NO_HALF_CLOSE),
	    "KNC_OPT_NO_HALF_CLOSE did not disable");

	knc_set_opt(ctx, KNC_OPT_SENDCMDS, 1);
	check(knc_get_opt(ctx, KNC_OPT_SENDCMDS),
	    "KNC_OPT_SENDCMDS did not enable");

	knc_set_opt(ctx, KNC_OPT_SENDCMDS, 0);
	check(!knc_get_opt(ctx, KNC_OPT_SENDCMDS),
	    "KNC_OPT_SENDCMDS did not disable");

	knc_ctx_destroy(ctx);
}

static void
test_max_recv_packet_option_enables_commands(void)
{
	knc_ctx	ctx;

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	check(knc_get_opt(ctx, KNC_OPT_MAX_RECV_PACKET) ==
	    KNC_DEFAULT_MAX_RECV_PACKET,
	    "KNC_OPT_MAX_RECV_PACKET had wrong default");
	check(!knc_get_opt(ctx, KNC_OPT_SENDCMDS),
	    "KNC_OPT_SENDCMDS defaulted to enabled");

	knc_set_opt(ctx, KNC_OPT_MAX_RECV_PACKET,
	    KNC_DEFAULT_MAX_RECV_PACKET + 4096);
	check(knc_get_opt(ctx, KNC_OPT_MAX_RECV_PACKET) ==
	    KNC_DEFAULT_MAX_RECV_PACKET + 4096,
	    "KNC_OPT_MAX_RECV_PACKET did not update");
	check(knc_get_opt(ctx, KNC_OPT_SENDCMDS),
	    "KNC_OPT_MAX_RECV_PACKET did not enable commands");

	knc_ctx_destroy(ctx);
}

static void
test_max_recv_packet_is_capped_at_wire_limit(void)
{
	char	 cap[64];
	knc_ctx	 ctx;
	int	 len;

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	knc_set_opt(ctx, KNC_OPT_MAX_RECV_PACKET, INT_MAX);
	check(knc_get_opt(ctx, KNC_OPT_MAX_RECV_PACKET) == KNC_MAX_WIRELEN,
	    "local max receive packet exceeded wire limit");

	len = snprintf(cap, sizeof(cap), "max_recv_packet=%zu\n",
	    (size_t)KNC_MAX_WIRELEN + 1);
	check(len > 0 && (size_t)len < sizeof(cap),
	    "peer max receive capability did not fit");
	cmd_capability(ctx, 0, cap, (size_t)len);
	check(ctx->peer_max_recv_packet == KNC_MAX_WIRELEN,
	    "peer max receive packet exceeded wire limit");

	knc_ctx_destroy(ctx);
}

static void
test_capability_command_updates_peer_recv_limit(void)
{
	knc_ctx		ctx;
	const char	cap[] = "max_recv_packet=131072\n";
	const char	small[] = "max_recv_packet=1024\n";

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	check(ctx->peer_max_recv_packet == KNC_DEFAULT_MAX_RECV_PACKET,
	    "peer max receive packet had wrong default");

	cmd_capability(ctx, 0, (void *)small, strlen(small));
	check(ctx->peer_max_recv_packet == KNC_DEFAULT_MAX_RECV_PACKET,
	    "small peer max receive packet lowered legacy limit");

	cmd_capability(ctx, 0, (void *)cap, strlen(cap));
	check(ctx->peer_max_recv_packet == 131072,
	    "capability did not update peer max receive packet");

	knc_ctx_destroy(ctx);
}

static void
test_read_packet_accepts_grace_over_local_recv_limit(void)
{
	knc_ctx		ctx;
	void		*payload;
	void		*buf;
	size_t		 len;
	size_t		 ret;
	uint32_t	 netlen;

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");

	len = KNC_DEFAULT_MAX_RECV_PACKET + KNC_PACKET_GRACE;
	payload = calloc(1, len);
	check(payload != NULL, "calloc failed");

	netlen = htonl((uint32_t)len);
	check(put_stream(&ctx->raw_recv, &netlen, sizeof(netlen)) ==
	    sizeof(netlen), "packet length put failed");
	check(put_stream(&ctx->raw_recv, payload, len) == len,
	    "packet payload put failed");

	ret = read_packet(ctx, &ctx->raw_recv, &buf);
	check(ret == len, "packet grace was not accepted");
	check_no_error(ctx, "packet grace set an error");

	free(payload);
	knc_ctx_destroy(ctx);
}

static void
test_read_packet_rejects_beyond_local_recv_limit_grace(void)
{
	knc_ctx		ctx;
	void		*buf;
	size_t		 len;
	size_t		 ret;
	uint32_t	 netlen;

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");

	len = KNC_DEFAULT_MAX_RECV_PACKET + KNC_PACKET_GRACE + 1;
	netlen = htonl((uint32_t)len);
	check(put_stream(&ctx->raw_recv, &netlen, sizeof(netlen)) ==
	    sizeof(netlen), "packet length put failed");

	ret = read_packet(ctx, &ctx->raw_recv, &buf);
	check(ret == 0, "oversized packet returned data");
	check(knc_error(ctx) == KNC_ERROR_PROTO,
	    "oversized packet was not a protocol error");

	knc_ctx_destroy(ctx);
}

static void
test_local_read_eof_does_not_queue_command_by_default(void)
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
	check(knc_pending(ctx, KNC_DIR_SEND) == 0,
	    "local read EOF queued a command by default");

	close(fds[0]);
	knc_ctx_destroy(ctx);
}

static void
test_local_read_eof_queues_send_eof_with_commands(void)
{
	knc_ctx	ctx;
	int	fds[2];
	int	ret;

	check(pipe(fds) == 0, "pipe failed");
	close(fds[1]);

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	knc_set_opt(ctx, KNC_OPT_SENDCMDS, 1);
	knc_set_local_fds(ctx, fds[0], -1);

	ret = knc_fill(ctx, KNC_DIR_SEND);
	check(ret == 0, "command local read EOF returned an error");
	check_no_error(ctx, "command local read EOF set an error");
	check(!(ctx->open & OPEN_WRITE),
	    "command local read EOF left write side open");
	check(ctx->open & OPEN_READ, "command local read EOF closed read side");
	check(knc_pending(ctx, KNC_DIR_SEND) == 1,
	    "command local read EOF did not queue exactly one EOF command");

	close(fds[0]);
	knc_ctx_destroy(ctx);
}

static void
test_no_half_close_local_read_eof_closes_both_sides_by_default(void)
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
	check(knc_pending(ctx, KNC_DIR_SEND) == 0,
	    "no-half-close local read EOF queued commands by default");

	close(fds[0]);
	knc_ctx_destroy(ctx);
}

static void
test_no_half_close_local_read_eof_queues_commands_when_enabled(void)
{
	knc_ctx	ctx;
	int	fds[2];
	int	ret;

	check(pipe(fds) == 0, "pipe failed");
	close(fds[1]);

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	knc_set_opt(ctx, KNC_OPT_SENDCMDS, 1);
	knc_set_opt(ctx, KNC_OPT_NO_HALF_CLOSE, 1);
	knc_set_local_fds(ctx, fds[0], -1);

	ret = knc_fill(ctx, KNC_DIR_SEND);
	check(ret == 0, "command no-half-close EOF returned an error");
	check_no_error(ctx, "command no-half-close EOF set an error");
	check(ctx->open == 0, "command no-half-close EOF left a side open");
	check(knc_pending(ctx, KNC_DIR_SEND) == 2,
	    "command no-half-close EOF did not queue both EOF commands");

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
	check(knc_pending(ctx, KNC_DIR_SEND) == 0,
	    "local write EPIPE queued a command by default");

	close(fds[0]);
	knc_ctx_destroy(ctx);
}

static void
test_local_write_epipe_queues_receive_eof_with_commands(void)
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
	knc_set_opt(ctx, KNC_OPT_SENDCMDS, 1);
	knc_set_local_fds(ctx, -1, fds[0]);
	put_stream(&ctx->cooked_recv, "x", 1);

	ret = knc_flush(ctx, KNC_DIR_RECV, 0);
	check(ret == 0, "command local write EPIPE returned an error");
	check_no_error(ctx, "command local write EPIPE set an error");
	check(!(ctx->open & OPEN_READ),
	    "command local write EPIPE left read side open");
	check(ctx->open & OPEN_WRITE,
	    "command local write EPIPE closed write side");
	check(knc_pending(ctx, KNC_DIR_RECV) == 0,
	    "command local write EPIPE left receive data pending");
	check(knc_pending(ctx, KNC_DIR_SEND) == 1,
	    "command local write EPIPE did not queue receive EOF command");

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

static void
test_remote_read_eof_closes_local_write_after_receive_drain(void)
{
	knc_ctx	ctx;
	char	buf;
	int	fds[2];
	int	ret;

	check(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0,
	    "socketpair failed");

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	ctx->state = STATE_SESSION;
	knc_set_local_fds(ctx, -1, fds[0]);
	put_stream(&ctx->cooked_recv, "x", 1);

	knc_remote_read_eof(ctx);
	ret = recv(fds[1], &buf, sizeof(buf), MSG_DONTWAIT);
	check(ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
	    "remote read EOF closed local write before receive drain");

	ret = knc_flush(ctx, KNC_DIR_RECV, 0);
	check(ret == 0, "receive flush after remote EOF returned an error");
	check_no_error(ctx, "receive flush after remote EOF set an error");
	check(read(fds[1], &buf, sizeof(buf)) == 1,
	    "receive flush did not deliver pending data");
	check(buf == 'x', "receive flush delivered wrong data");
	check(read(fds[1], &buf, sizeof(buf)) == 0,
	    "remote read EOF did not close local write after receive drain");

	close(fds[1]);
	knc_ctx_destroy(ctx);
}

static void
test_local_flush_writes_to_pipe(void)
{
	knc_ctx	ctx;
	char	buf[4];
	int	fds[2];
	int	ret;

	check(pipe(fds) == 0, "pipe failed");

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	ctx->state = STATE_SESSION;
	knc_set_local_fds(ctx, -1, fds[1]);
	put_stream(&ctx->cooked_recv, "pipe", 4);

	ret = knc_flush(ctx, KNC_DIR_RECV, 0);
	check(ret == 0, "local flush to pipe returned an error");
	check_no_error(ctx, "local flush to pipe set an error");
	check(read(fds[0], buf, sizeof(buf)) == (ssize_t)sizeof(buf),
	    "local flush to pipe did not write data");
	check(memcmp(buf, "pipe", sizeof(buf)) == 0,
	    "local flush to pipe wrote wrong data");

	close(fds[0]);
	close(fds[1]);
	knc_ctx_destroy(ctx);
}

static void
test_remote_read_eof_hides_receive_fds(void)
{
	knc_ctx	ctx;
	int	local[2];
	int	net[2];

	check(socketpair(AF_UNIX, SOCK_STREAM, 0, local) == 0,
	    "local socketpair failed");
	check(socketpair(AF_UNIX, SOCK_STREAM, 0, net) == 0,
	    "net socketpair failed");

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	ctx->state = STATE_SESSION;
	knc_set_local_fds(ctx, local[0], local[0]);
	knc_set_net_fds(ctx, net[0], net[0]);

	knc_remote_read_eof(ctx);
	check(knc_get_net_rfd(ctx) == -1,
	    "remote read EOF left network read fd visible");
	check(knc_get_local_wfd(ctx) == -1,
	    "remote read EOF left local write fd visible");
	check(knc_get_net_wfd(ctx) == net[0],
	    "remote read EOF hid network write fd");
	check(knc_get_local_rfd(ctx) == local[0],
	    "remote read EOF hid local read fd");

	close(local[0]);
	close(local[1]);
	close(net[0]);
	close(net[1]);
	knc_ctx_destroy(ctx);
}

static void
test_network_write_eof_hides_send_fds(void)
{
	knc_ctx	ctx;
	int	local[2];
	int	net[2];

	check(socketpair(AF_UNIX, SOCK_STREAM, 0, local) == 0,
	    "local socketpair failed");
	check(socketpair(AF_UNIX, SOCK_STREAM, 0, net) == 0,
	    "net socketpair failed");

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	ctx->state = STATE_SESSION;
	knc_set_local_fds(ctx, local[0], local[0]);
	knc_set_net_fds(ctx, net[0], net[0]);

	knc_network_write_eof(ctx);
	check(knc_get_local_rfd(ctx) == -1,
	    "network write EOF left local read fd visible");
	check(knc_get_net_wfd(ctx) == -1,
	    "network write EOF left network write fd visible");
	check(knc_get_local_wfd(ctx) == local[0],
	    "network write EOF hid local write fd");
	check(knc_get_net_rfd(ctx) == net[0],
	    "network write EOF hid network read fd");

	close(local[0]);
	close(local[1]);
	close(net[0]);
	close(net[1]);
	knc_ctx_destroy(ctx);
}

int
main(void)
{

	test_no_half_close_option();
	test_max_recv_packet_option_enables_commands();
	test_max_recv_packet_is_capped_at_wire_limit();
	test_capability_command_updates_peer_recv_limit();
	test_read_packet_accepts_grace_over_local_recv_limit();
	test_read_packet_rejects_beyond_local_recv_limit_grace();
	test_local_read_eof_does_not_queue_command_by_default();
	test_local_read_eof_queues_send_eof_with_commands();
	test_no_half_close_local_read_eof_closes_both_sides_by_default();
	test_no_half_close_local_read_eof_queues_commands_when_enabled();
	test_network_eof_after_authentication_is_eof();
	test_network_mid_packet_eof_is_protocol_error();
	test_local_write_epipe_queues_receive_eof();
	test_local_write_epipe_queues_receive_eof_with_commands();
	test_network_write_epipe_closes_write_side();
	test_remote_read_eof_closes_local_write_after_receive_drain();
	test_local_flush_writes_to_pipe();
	test_remote_read_eof_hides_receive_fds();
	test_network_write_eof_hides_send_fds();

	return 0;
}
