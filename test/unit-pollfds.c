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

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
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
test_fd_zero_is_pollable(void)
{
	knc_callback	cbs[4];
	struct pollfd	fds[4];
	knc_ctx		ctx;
	nfds_t		nfds;
	nfds_t		i;
	int		found;

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");

	knc_set_net_fds(ctx, 0, -1);
	nfds = knc_get_pollfds(ctx, fds, cbs, 4);

	found = 0;
	for (i = 0; i < nfds; i++) {
		if (fds[i].fd == 0 && (fds[i].events & POLLIN))
			found = 1;
	}

	check(found, "network read fd 0 was not returned by knc_get_pollfds");
	knc_ctx_destroy(ctx);
}

static void
test_pollhup_services_local_read(void)
{
	knc_callback	cbs[4];
	struct pollfd	fds[4];
	knc_ctx		ctx;
	nfds_t		nfds;
	nfds_t		i;
	int		pipefds[2];
	int		found;

	check(pipe(pipefds) == 0, "pipe failed");
	close(pipefds[1]);

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	ctx->state = STATE_SESSION;

	knc_set_local_fds(ctx, pipefds[0], -1);
	nfds = knc_get_pollfds(ctx, fds, cbs, 4);

	found = 0;
	for (i = 0; i < nfds; i++) {
		if (fds[i].fd == pipefds[0] && (fds[i].events & POLLIN)) {
			fds[i].revents = POLLHUP;
			found = 1;
		} else
			fds[i].revents = 0;
	}

	check(found, "local read fd was not returned by knc_get_pollfds");
	knc_service_pollfds(ctx, fds, cbs, nfds);
	check(!knc_error(ctx), "POLLHUP service set an error");
	check(!(ctx->open & OPEN_WRITE),
	    "POLLHUP service left write side open");
	check(knc_pending(ctx, KNC_DIR_SEND) == 0,
	    "POLLHUP queued a command by default");

	close(pipefds[0]);
	knc_ctx_destroy(ctx);
}

static void
test_pollerr_services_local_read(void)
{
	knc_callback	cbs[4];
	struct pollfd	fds[4];
	knc_ctx		ctx;
	nfds_t		nfds;
	nfds_t		i;
	int		pipefds[2];
	int		found;

	check(pipe(pipefds) == 0, "pipe failed");
	close(pipefds[1]);

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	ctx->state = STATE_SESSION;

	knc_set_local_fds(ctx, pipefds[0], -1);
	nfds = knc_get_pollfds(ctx, fds, cbs, 4);

	found = 0;
	for (i = 0; i < nfds; i++) {
		if (fds[i].fd == pipefds[0] && (fds[i].events & POLLIN)) {
			fds[i].revents = POLLERR;
			found = 1;
		} else
			fds[i].revents = 0;
	}

	check(found, "local read fd was not returned by knc_get_pollfds");
	knc_service_pollfds(ctx, fds, cbs, nfds);
	check(!knc_error(ctx), "POLLERR service set an error");
	check(!(ctx->open & OPEN_WRITE),
	    "POLLERR service left write side open");
	check(knc_pending(ctx, KNC_DIR_SEND) == 0,
	    "POLLERR queued a command by default");

	close(pipefds[0]);
	knc_ctx_destroy(ctx);
}

static void
test_pollnval_services_local_read_error(void)
{
	knc_callback	cbs[4];
	struct pollfd	fds[4];
	knc_ctx		ctx;
	nfds_t		nfds;
	nfds_t		i;
	int		pipefds[2];
	int		found;

	check(pipe(pipefds) == 0, "pipe failed");

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");
	ctx->state = STATE_SESSION;

	knc_set_local_fds(ctx, pipefds[0], -1);
	nfds = knc_get_pollfds(ctx, fds, cbs, 4);

	found = 0;
	for (i = 0; i < nfds; i++) {
		if (fds[i].fd == pipefds[0] && (fds[i].events & POLLIN)) {
			fds[i].revents = POLLNVAL;
			found = 1;
		} else
			fds[i].revents = 0;
	}

	close(pipefds[0]);
	close(pipefds[1]);

	check(found, "local read fd was not returned by knc_get_pollfds");
	knc_service_pollfds(ctx, fds, cbs, nfds);
	check(knc_error(ctx), "POLLNVAL service did not set an error");

	knc_ctx_destroy(ctx);
}

static void
test_local_fds_are_hidden_before_authentication(void)
{
	knc_callback	cbs[4];
	struct pollfd	fds[4];
	knc_ctx		ctx;
	nfds_t		nfds;
	int		pipefds[2];

	check(pipe(pipefds) == 0, "pipe failed");

	ctx = knc_ctx_init();
	check(ctx != NULL, "knc_ctx_init failed");

	knc_set_local_fds(ctx, pipefds[0], pipefds[1]);
	nfds = knc_get_pollfds(ctx, fds, cbs, 4);
	check(nfds == 0, "unauthenticated local fds were returned");

	close(pipefds[0]);
	close(pipefds[1]);
	knc_ctx_destroy(ctx);
}

int
main(void)
{

	test_fd_zero_is_pollable();
	test_local_fds_are_hidden_before_authentication();
	test_pollhup_services_local_read();
	test_pollerr_services_local_read();
	test_pollnval_services_local_read_error();

	return 0;
}
