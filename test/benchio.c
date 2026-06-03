/*-
 * Copyright 2026  Morgan Stanley and Co. Incorporated
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
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFSIZE		(1024 * 1024)

static void
usage(const char *prog)
{

	fprintf(stderr, "usage: %s source <bytes>\n", prog);
	fprintf(stderr, "       %s sink <bytes> [marker]\n", prog);
	exit(2);
}

static uint64_t
parse_size(const char *prog, const char *s)
{
	char		*end;
	uint64_t	 ret;

	errno = 0;
	ret = strtoull(s, &end, 10);
	if (errno || *end)
		usage(prog);

	return ret;
}

static int
write_all(int fd, const void *buf, size_t len)
{
	const char	*p = buf;
	ssize_t		 ret;

	while (len) {
		ret = write(fd, p, len);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0)
			return -1;
		p += ret;
		len -= ret;
	}

	return 0;
}

static int
write_marker(const char *path, uint64_t total)
{
	char	 buf[64];
	int	 len;
	FILE	*f;

	if (!path)
		return 0;

	f = fopen(path, "w");
	if (!f)
		return -1;

	len = snprintf(buf, sizeof(buf), "%llu\n",
	    (unsigned long long)total);
	if (len < 0 || (size_t)len >= sizeof(buf)) {
		fclose(f);
		return -1;
	}

	if (fwrite(buf, 1, (size_t)len, f) != (size_t)len) {
		fclose(f);
		return -1;
	}

	return fclose(f);
}

static int
source(uint64_t total)
{
	char		*buf;
	uint64_t	 left;
	size_t		 chunk;
	int		 ret;

	buf = calloc(1, BUFSIZE);
	if (!buf)
		return 1;

	for (left = total; left > 0; left -= chunk) {
		chunk = left > BUFSIZE ? BUFSIZE : (size_t)left;
		ret = write_all(STDOUT_FILENO, buf, chunk);
		if (ret < 0) {
			free(buf);
			return 1;
		}
	}

	free(buf);
	return 0;
}

static int
sink(uint64_t total, const char *marker)
{
	char		*buf;
	uint64_t	 left;
	size_t		 wanted;
	ssize_t		 ret;

	buf = malloc(BUFSIZE);
	if (!buf)
		return 1;

	left = total;
	while (left > 0) {
		wanted = left > BUFSIZE ? BUFSIZE : (size_t)left;
		ret = read(STDIN_FILENO, buf, wanted);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			return 1;
		}
		if (ret == 0) {
			free(buf);
			return 3;
		}
		left -= ret;
	}

	free(buf);
	if (write_marker(marker, total) < 0)
		return 1;

	return 0;
}

int
main(int argc, char **argv)
{
	uint64_t	total;

	if (argc < 3 || argc > 4)
		usage(argv[0]);

	total = parse_size(argv[0], argv[2]);

	if (!strcmp(argv[1], "source") && argc == 3)
		return source(total);

	if (!strcmp(argv[1], "sink"))
		return sink(total, argc == 4 ? argv[3] : NULL);

	usage(argv[0]);
	return 2;
}
