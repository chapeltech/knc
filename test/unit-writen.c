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
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Include the implementation so Automake only sees a local test source. */
#include "../bin/gssstdio.c"

char		_log_buff[2048];
gss_OID		global_mech = GSS_C_NO_OID;
prefs_t		prefs = { .debug_level = -1 };

const char *
vlog(const char *fmt, ...)
{

	(void)fmt;
	return "";
}

static void
fail(const char *message)
{

	fprintf(stderr, "%s\n", message);
	exit(1);
}

static void
fill_pattern(unsigned char *buf, size_t len)
{
	uint32_t state = 0x6d2b79f5;
	size_t	 offset;

	for (offset = 0; offset < len; offset++) {
		state ^= state << 13;
		state ^= state >> 17;
		state ^= state << 5;
		buf[offset] = (unsigned char)(state >> 24);
	}
}

static size_t
measure_pipe_capacity(int read_fd, int write_fd)
{
	unsigned char	buf[4096];
	size_t		capacity = 0;
	size_t		left;
	ssize_t		len;

	memset(buf, 0, sizeof(buf));
	for (;;) {
		len = write(write_fd, buf, sizeof(buf));
		if (len > 0) {
			capacity += (size_t)len;
			continue;
		}
		if (len == -1 && errno == EINTR)
			continue;
		if (len == -1 && errno == EAGAIN)
			break;
		fail("could not fill non-blocking pipe");
	}

	left = capacity;
	while (left > 0) {
		len = read(read_fd, buf,
		    left < sizeof(buf) ? left : sizeof(buf));
		if (len == -1 && errno == EINTR)
			continue;
		if (len <= 0)
			fail("could not drain pipe after measuring capacity");
		left -= (size_t)len;
	}

	return capacity;
}

int
main(void)
{
	unsigned char	*payload;
	unsigned char	*received;
	unsigned char	 buf[4096];
	struct pollfd	 pfd;
	size_t		 capacity;
	size_t		 payload_len;
	size_t		 received_len = 0;
	ssize_t		 len;
	pid_t		 child;
	pid_t		 waited;
	int		 fds[2];
	int		 flags;
	int		 status;

	if (pipe(fds) == -1)
		fail("pipe failed");
	flags = fcntl(fds[1], F_GETFL);
	if (flags == -1 || fcntl(fds[1], F_SETFL, flags | O_NONBLOCK) == -1)
		fail("could not make pipe non-blocking");

	capacity = measure_pipe_capacity(fds[0], fds[1]);
	if (capacity == 0 || capacity > ((size_t)INT_MAX - 123) / 4)
		fail("unexpected pipe capacity");

	payload_len = capacity * 4 + 123;
	payload = malloc(payload_len);
	received = malloc(payload_len);
	if (payload == NULL || received == NULL)
		fail("malloc failed");
	fill_pattern(payload, payload_len);

	child = fork();
	if (child == -1)
		fail("fork failed");
	if (child == 0) {
		close(fds[0]);
		status = writen(fds[1], payload, (ssize_t)payload_len);
		close(fds[1]);
		_exit(status == (int)payload_len ? 0 : 1);
	}
	close(fds[1]);

	/* No reader is active yet, so this first write cannot be complete. */
	pfd.fd = fds[0];
	pfd.events = POLLIN;
	do {
		status = poll(&pfd, 1, 5000);
	} while (status == -1 && errno == EINTR);
	if (status != 1 || (pfd.revents & POLLIN) == 0)
		fail("writer did not make the expected partial write");

	for (;;) {
		len = read(fds[0], buf, sizeof(buf));
		if (len > 0) {
			if (received_len + (size_t)len <= payload_len)
				memcpy(received + received_len, buf,
				    (size_t)len);
			received_len += (size_t)len;
			continue;
		}
		if (len == -1 && errno == EINTR)
			continue;
		break;
	}
	if (len == -1)
		fail("pipe read failed");
	close(fds[0]);
	do {
		waited = waitpid(child, &status, 0);
	} while (waited == -1 && errno == EINTR);
	if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		fail("writen did not report the complete payload");

	if (received_len != payload_len) {
		fprintf(stderr, "received %zu bytes, expected %zu\n",
		    received_len, payload_len);
		return 1;
	}
	if (memcmp(received, payload, payload_len) != 0) {
		fprintf(stderr, "received payload differs from sent payload\n");
		return 1;
	}

	free(payload);
	free(received);
	return 0;
}
