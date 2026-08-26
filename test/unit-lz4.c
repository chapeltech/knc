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

static knc_ctx
recv_ctx(size_t limit)
{
	knc_ctx	ctx;

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	ctx->state = STATE_SESSION;
	ctx->lz4_recv = 1;
	ctx->recvinbufsiz = limit;
	check(knc_lz4_start_recv(ctx) == 0,
	    "LZ4 receive context creation failed");
	return ctx;
}

static void *
compress_frame(const void *input, size_t input_len, size_t *frame_len)
{
	LZ4F_preferences_t	 prefs;
	void			*frame;
	size_t			 cap;
	size_t			 ret;

	knc_lz4_preferences(&prefs);
	cap = LZ4F_compressFrameBound(input_len, &prefs);
	frame = malloc(cap);
	check(frame != NULL, "LZ4 frame allocation failed");
	ret = LZ4F_compressFrame(frame, cap, input, input_len, &prefs);
	check(!LZ4F_isError(ret), "LZ4 frame compression failed");
	*frame_len = ret;
	return frame;
}

static void
queue_frame(knc_ctx ctx, void *frame, size_t frame_len)
{

	check(put_malloc_stream(ctx, &ctx->sushi_recv, frame, frame_len) == 0,
	    "failed to queue compressed frame");
}

static size_t
drain_zeros(knc_ctx ctx)
{
	unsigned char	*buf;
	size_t		 avail;
	size_t		 i;
	size_t		 total = 0;

	while ((avail = get_ostream(&ctx->cooked_recv, (void **)&buf,
	    stream_avail(&ctx->cooked_recv))) != 0) {
		for (i = 0; i < avail; i++)
			check(buf[i] == 0, "decompressed data was corrupted");
		check(stream_drain(&ctx->cooked_recv, avail) == (ssize_t)avail,
		    "failed to drain decompressed data");
		total += avail;
	}

	return total;
}

static void
test_complete_frame(void)
{
	unsigned char	 input[8192];
	knc_ctx		 ctx;
	void		*frame;
	size_t		 frame_len;

	memset(input, 0, sizeof(input));
	frame = compress_frame(input, sizeof(input), &frame_len);
	ctx = recv_ctx(sizeof(input));
	queue_frame(ctx, frame, frame_len);

	check(knc_process_sushi_recv(ctx) == 0,
	    "complete LZ4 frame was rejected");
	check(ctx->lz4_recv_finished, "complete LZ4 frame was not finished");
	check(drain_zeros(ctx) == sizeof(input),
	    "complete LZ4 frame produced the wrong length");
	knc_lz4_mark_recv_eof(ctx);
	check(!knc_error(ctx), "complete LZ4 frame failed at EOF");

	knc_ctx_destroy(ctx);
}

static void
test_truncated_frame(void)
{
	unsigned char	 input[8192];
	knc_ctx		 ctx;
	void		*frame;
	size_t		 frame_len;

	memset(input, 0, sizeof(input));
	frame = compress_frame(input, sizeof(input), &frame_len);
	check(frame_len > 4, "compressed frame was unexpectedly short");
	ctx = recv_ctx(sizeof(input));
	queue_frame(ctx, frame, frame_len - 4);

	check(knc_process_sushi_recv(ctx) == 0,
	    "truncated LZ4 frame failed before EOF");
	check(!ctx->lz4_recv_finished,
	    "truncated LZ4 frame was marked complete");
	knc_lz4_mark_recv_eof(ctx);
	check(!knc_error(ctx),
	    "backpressured truncated frame failed before output drained");
	drain_zeros(ctx);
	check(knc_process_sushi_recv(ctx) < 0,
	    "truncated LZ4 frame was accepted after output drained");
	check(knc_error(ctx), "truncated LZ4 frame was accepted at EOF");

	knc_ctx_destroy(ctx);
}

static void
test_trailing_frame(void)
{
	unsigned char	 input[1024];
	knc_ctx		 ctx;
	void		*first;
	void		*second;
	void		*joined;
	size_t		 first_len;
	size_t		 second_len;

	memset(input, 0, sizeof(input));
	first = compress_frame(input, sizeof(input), &first_len);
	second = compress_frame(input, sizeof(input), &second_len);
	joined = malloc(first_len + second_len);
	check(joined != NULL, "joined LZ4 frame allocation failed");
	memcpy(joined, first, first_len);
	memcpy((char *)joined + first_len, second, second_len);
	free(first);
	free(second);

	ctx = recv_ctx(2 * sizeof(input));
	queue_frame(ctx, joined, first_len + second_len);
	check(knc_process_sushi_recv(ctx) < 0,
	    "trailing LZ4 frame was accepted");
	check(knc_error(ctx), "trailing LZ4 frame did not set an error");

	knc_ctx_destroy(ctx);
}

static void
test_decompression_backpressure(void)
{
	unsigned char	*input;
	knc_ctx		 ctx;
	void		*frame;
	size_t		 frame_len;
	size_t		 total = 0;
	size_t		 input_len = 512 * 1024;
	size_t		 limit = 16 * 1024;

	input = calloc(1, input_len);
	check(input != NULL, "backpressure input allocation failed");
	frame = compress_frame(input, input_len, &frame_len);
	free(input);

	ctx = recv_ctx(limit);
	queue_frame(ctx, frame, frame_len);
	while (!ctx->lz4_recv_finished && !knc_error(ctx)) {
		check(knc_process_sushi_recv(ctx) == 0,
		    "backpressured LZ4 frame was rejected");
		check(stream_avail(&ctx->cooked_recv) <= limit,
		    "LZ4 decompression exceeded receive buffer limit");
		total += drain_zeros(ctx);
	}
	total += drain_zeros(ctx);
	check(!knc_error(ctx), "backpressured LZ4 frame set an error");
	check(total == input_len,
	    "backpressured LZ4 frame produced the wrong length");

	knc_ctx_destroy(ctx);
}

static void
test_gss_buffer_ownership_on_error(void)
{
	gss_buffer_desc	 display;
	gss_buffer_desc	 input;
	gss_name_t	 name;
	knc_ctx		 ctx;
	OM_uint32	 maj;
	OM_uint32	 min;

	input.value = (void *)"not an LZ4 frame";
	input.length = strlen(input.value);
	maj = gss_import_name(&min, &input, GSS_C_NT_USER_NAME, &name);
	check(maj == GSS_S_COMPLETE, "gss_import_name failed");
	maj = gss_display_name(&min, name, &display, NULL);
	check(maj == GSS_S_COMPLETE, "gss_display_name failed");
	gss_release_name(&min, &name);

	ctx = recv_ctx(64 * 1024);
	check(knc_put_unwrapped_data(ctx, &display) < 0,
	    "malformed LZ4 GSS buffer was accepted");
	check(display.value == NULL && display.length == 0,
	    "owned GSS buffer was left with the caller");
	knc_ctx_destroy(ctx);
}

static knc_ctx
negotiation_ctx(void)
{
	knc_ctx	ctx;

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	knc_set_opt(ctx, KNC_OPT_COMPRESS_LZ4, 1);
	return ctx;
}

static void
test_lz4_ack_requires_request(void)
{
	knc_ctx	ctx;

	ctx = negotiation_ctx();
	check(cmd_compress_lz4_ok(ctx, 0, NULL, 0) < 0,
	    "unsolicited LZ4 acknowledgement was accepted");
	check(knc_error(ctx) == KNC_ERROR_PROTO,
	    "unsolicited LZ4 acknowledgement was not a protocol error");
	knc_ctx_destroy(ctx);
}

static void
test_lz4_ack_cannot_restart_receive_stream(void)
{
	knc_ctx	ctx;

	ctx = negotiation_ctx();
	check(knc_queue_lz4_request(ctx) == 0,
	    "failed to queue LZ4 request");
	check(cmd_compress_lz4_ok(ctx, 0, NULL, 0) == 0,
	    "valid LZ4 acknowledgement was rejected");
	check(ctx->lz4_recv, "valid LZ4 acknowledgement was ignored");
	check(cmd_compress_lz4_ok(ctx, 0, NULL, 0) < 0,
	    "duplicate LZ4 acknowledgement was accepted");
	check(knc_error(ctx) == KNC_ERROR_PROTO,
	    "duplicate LZ4 acknowledgement was not a protocol error");
	knc_ctx_destroy(ctx);
}

static void
test_lz4_request_cannot_restart_send_stream(void)
{
	knc_ctx	ctx;

	ctx = negotiation_ctx();
	check(cmd_compress_lz4(ctx, 7, NULL, 0) == 0,
	    "valid LZ4 request was rejected");
	check(ctx->lz4_send_pending, "LZ4 acknowledgement was not pending");
	check(cmd_compress_lz4(ctx, 7, NULL, 0) < 0,
	    "duplicate LZ4 request was accepted");
	check(knc_error(ctx) == KNC_ERROR_PROTO,
	    "duplicate LZ4 request was not a protocol error");
	knc_ctx_destroy(ctx);
}

static void
test_lz4_negotiation_commands_reject_data(void)
{
	unsigned char	data = 0;
	knc_ctx		ctx;

	ctx = negotiation_ctx();
	check(cmd_compress_lz4(ctx, 0, &data, sizeof(data)) < 0,
	    "LZ4 request with data was accepted");
	check(knc_error(ctx) == KNC_ERROR_PROTO,
	    "LZ4 request data was not a protocol error");
	knc_ctx_destroy(ctx);

	ctx = negotiation_ctx();
	check(knc_queue_lz4_request(ctx) == 0,
	    "failed to queue LZ4 request");
	check(cmd_compress_lz4_ok(ctx, 0, &data, sizeof(data)) < 0,
	    "LZ4 acknowledgement with data was accepted");
	check(knc_error(ctx) == KNC_ERROR_PROTO,
	    "LZ4 acknowledgement data was not a protocol error");
	knc_ctx_destroy(ctx);
}

int
main(void)
{

	test_complete_frame();
	test_truncated_frame();
	test_trailing_frame();
	test_decompression_backpressure();
	test_gss_buffer_ownership_on_error();
	test_lz4_ack_requires_request();
	test_lz4_ack_cannot_restart_receive_stream();
	test_lz4_request_cannot_restart_send_stream();
	test_lz4_negotiation_commands_reject_data();
	return 0;
}
