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

#include <netinet/in.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/libknc.h"

static void
check(int condition, const char *message)
{

	if (!condition) {
		fprintf(stderr, "%s\n", message);
		exit(1);
	}
}

static int		accept_calls;
static int		release_buffer_calls;
static const char	accept_output[] = "acceptor first";

static OM_uint32
test_gss_accept_sec_context(OM_uint32 *minor_status,
    gss_ctx_id_t *context_handle, gss_cred_id_t acceptor_cred_handle,
    gss_buffer_t input_token_buffer,
    gss_channel_bindings_t input_chan_bindings, gss_name_t *src_name,
    gss_OID *mech_type, gss_buffer_t output_token, OM_uint32 *ret_flags,
    OM_uint32 *time_rec, gss_cred_id_t *delegated_cred_handle)
{

	accept_calls++;
	check(input_token_buffer != GSS_C_NO_BUFFER,
	    "acceptor-first input token was absent");
	check(input_token_buffer->length == 0,
	    "acceptor-first input token was not empty");

	output_token->length = sizeof(accept_output) - 1;
	output_token->value = malloc(output_token->length);
	check(output_token->value != NULL, "malloc failed");
	memcpy(output_token->value, accept_output, output_token->length);

	*minor_status = 0;
	*context_handle = GSS_C_NO_CONTEXT;
	return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
test_gss_release_buffer(OM_uint32 *minor_status, gss_buffer_t buffer)
{

	release_buffer_calls++;
	free(buffer->value);
	buffer->value = NULL;
	buffer->length = 0;
	*minor_status = 0;
	return GSS_S_COMPLETE;
}

#define gss_accept_sec_context	test_gss_accept_sec_context
#define gss_release_buffer	test_gss_release_buffer
#include "../lib/libknc.c"

static void
test_acceptor_first_disabled_by_default(void)
{
	knc_ctx	ctx;

	accept_calls = 0;

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");

	knc_accept(ctx);
	check(accept_calls == 0,
	    "knc_accept performed acceptor-first step by default");
	check(ctx->state == STATE_ACCEPT, "knc_accept set wrong state");
	check(knc_pending(ctx, KNC_DIR_SEND) == 0,
	    "passive accept queued output");

	knc_ctx_destroy(ctx);
}

static void
test_acceptor_first_queues_initial_token(void)
{
	uint32_t netlen;
	knc_ctx	ctx;
	void	*buf;
	size_t	len;

	accept_calls = 0;
	release_buffer_calls = 0;

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");

	knc_set_opt(ctx, KNC_OPT_ACCEPTOR_FIRST, 1);
	knc_accept(ctx);

	check(accept_calls == 1, "acceptor-first step was not performed");
	check(ctx->state == STATE_ACCEPT,
	    "acceptor-first accept did not continue");
	check(knc_pending(ctx, KNC_DIR_SEND) ==
	    sizeof(netlen) + sizeof(accept_output) - 1,
	    "acceptor-first output was not queued");

	len = get_ostream_contig(&ctx->cooked_send, &buf, sizeof(netlen));
	check(len == sizeof(netlen), "acceptor-first packet length missing");
	memcpy(&netlen, buf, sizeof(netlen));
	check(ntohl(netlen) == sizeof(accept_output) - 1,
	    "acceptor-first packet length mismatch");
	stream_drain(&ctx->cooked_send, len);

	len = get_ostream_contig(&ctx->cooked_send, &buf,
	    sizeof(accept_output) - 1);
	check(len == sizeof(accept_output) - 1,
	    "acceptor-first packet token missing");
	check(memcmp(buf, accept_output, sizeof(accept_output) - 1) == 0,
	    "acceptor-first packet token mismatch");

	knc_ctx_destroy(ctx);
	check(release_buffer_calls == 1,
	    "acceptor-first output token was not released");
}

int
main(void)
{

	test_acceptor_first_disabled_by_default();
	test_acceptor_first_queues_initial_token();

	return 0;
}
