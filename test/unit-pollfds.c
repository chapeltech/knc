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

#include <libknc.h>

static void
check(int condition, const char *message)
{

	if (!condition) {
		fprintf(stderr, "%s\n", message);
		exit(1);
	}
}

int
main(void)
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

	return 0;
}
