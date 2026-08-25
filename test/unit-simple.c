/* */

/*-
 * Copyright 2011 Roland C. Dowdeswell
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


#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libknc.h>

/*
 * On linux, you have to prepend + to optstring to cause sane argument
 * processing to occur.  We hardcode this here rather than rely on the
 * user to set POSIXLY_CORRECT because for programs with a syntax that
 * accepts another program which has arguments, the GNU convention is
 * particularly stupid.
 */
#ifdef linux
#define POS "+"
#else
#define POS
#endif

int  runserver(int);
int  runclient(int, const char *);
int  knc_loop(knc_ctx, int);
void usage(void);

/* Global variables */

int debug = 0;
int quiet = 0;
int transfer = 0;

void
usage(void)
{

	fprintf(stderr, "unit-simple [-dqx] service@hostname\n");
	exit(EXIT_FAILURE);
}

/*
 * unit-simple: a simple test of the libknc.
 *
 * The idea here is that we fork and the child assumes the role of a
 * KNC server whilst the parent assumes the role of a KNC client connecting
 * to it.  We construct a reasonable test of passing data back and forth
 * while checking for memory leaks in the library.
 */

int
main(int argc, char **argv)
{
	pid_t	pid;
	int	fds[2];
	int	kidret;
	int	ret;
	int	c;

	srandom(time(NULL));
 
        /* process arguments */
	while ((c = getopt(argc, argv, POS "dqx")) != -1) {
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'x':
			transfer = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	ret = socketpair(PF_LOCAL, SOCK_STREAM, 0, fds);
	if (ret == -1) {
		perror("socketpair");
		exit(1);
	}

	pid = fork();
	switch (pid) {
	case  0:
		close(fds[0]);
		ret = runserver(fds[1]);
		fprintf(stderr, "Child exiting = %d\n", ret);
		exit(ret);
	case -1:
		perror("fork");
		exit(1);
	default:
		close(fds[1]);
		ret = runclient(fds[0], argv[0]);
		break;
	}

	if (wait(&kidret) == -1) {
		perror("wait");
		kidret = 1;
	}

	if (ret)
		fprintf(stderr, "Parent failed.\n");

	if (WIFEXITED(kidret) && WEXITSTATUS(kidret) != 0)
		fprintf(stderr, "Child failed = %d\n", WEXITSTATUS(kidret));

	if (WIFSIGNALED(kidret))
		fprintf(stderr, "Child got hit with a %d sig%s.\n",
		    WTERMSIG(kidret), WCOREDUMP(kidret)?"(core dumped)":"");

	fprintf(stderr, "Parent exiting.\n");

	if (ret || kidret)
		return 1;

	return 0;
}

static void
no_sigpipe(int s)
{
#ifdef O_NOSIGPIPE
	int	flags;

	flags = fcntl(s, F_GETFL, 0);

	flags |= O_NOSIGPIPE;
	fcntl(s, F_SETFL, flags);
#else
	/* This code path will have bugs... */
	return;
#endif
}

int
runserver(int fd)
{
	knc_ctx		ctx;
	void		*token;
	size_t		token_len;
	unsigned	opts;
	int		newfd;
	uint32_t	offset;
	uint32_t	len;
	char		byte;

	fprintf(stderr, "S: pid == %d\n", getpid());

	no_sigpipe(fd);

	ctx = knc_ctx_init();

	knc_set_debug(ctx, debug);
	knc_set_debug_prefix(ctx, "S");
	knc_give_net_fd(ctx, fd);
	knc_accept(ctx);

	knc_authenticate(ctx);

	if (knc_error(ctx)) {
		fprintf(stderr, "S: knc_authenticate: %s\n", knc_errstr(ctx));
		exit(1);
	}

	if (transfer) {
		char		*client_before;
		char		*service_before;
		char		*mech_before;
		char		*client_after;
		char		*service_after;
		char		*mech_after;
		size_t		 client_before_len;
		size_t		 service_before_len;
		size_t		 mech_before_len;
		size_t		 client_after_len;
		size_t		 service_after_len;
		size_t		 mech_after_len;
		OM_uint32	 flags_before;

		if (knc_get_client_display_name(ctx, &client_before,
		    &client_before_len) == -1 ||
		    knc_get_service_display_name(ctx, &service_before,
		    &service_before_len) == -1 ||
		    knc_get_mech_display_name(ctx, &mech_before,
		    &mech_before_len) == -1) {
			fprintf(stderr, "S: display authenticated metadata: %s\n",
			    knc_errstr(ctx));
			exit(1);
		}
		flags_before = knc_get_ret_flags(ctx);
		newfd = dup(fd);
		if (newfd == -1) {
			perror("S: dup");
			exit(1);
		}
		if (knc_export_sec_context(ctx, &token, &token_len, &opts) == -1) {
			fprintf(stderr, "S: knc_export_sec_context: %s\n",
			    knc_errstr(ctx));
			exit(1);
		}
		knc_ctx_destroy(ctx);

		ctx = knc_ctx_init();
		knc_set_debug(ctx, debug);
		knc_set_debug_prefix(ctx, "S-imported");
		knc_give_net_fd(ctx, newfd);
		if (knc_import_sec_context(ctx, token, token_len, opts) == -1) {
			fprintf(stderr, "S: knc_import_sec_context: %s\n",
			    knc_errstr(ctx));
			knc_release_exported_sec_context(token, token_len);
			exit(1);
		}
		knc_release_exported_sec_context(token, token_len);

		if (knc_get_client_display_name(ctx, &client_after,
		    &client_after_len) == -1 ||
		    knc_get_service_display_name(ctx, &service_after,
		    &service_after_len) == -1 ||
		    knc_get_mech_display_name(ctx, &mech_after,
		    &mech_after_len) == -1) {
			fprintf(stderr, "S: display imported metadata: %s\n",
			    knc_errstr(ctx));
			exit(1);
		}
		if (client_before_len != client_after_len ||
		    memcmp(client_before, client_after, client_before_len) != 0 ||
		    service_before_len != service_after_len ||
		    memcmp(service_before, service_after,
		    service_before_len) != 0 ||
		    mech_before_len != mech_after_len ||
		    memcmp(mech_before, mech_after, mech_before_len) != 0 ||
		    flags_before != knc_get_ret_flags(ctx)) {
			fprintf(stderr, "S: imported authentication metadata changed\n");
			exit(1);
		}
		knc_free_display_name(client_before);
		knc_free_display_name(service_before);
		knc_free_display_name(mech_before);
		knc_free_display_name(client_after);
		knc_free_display_name(service_after);
		knc_free_display_name(mech_after);
	}

	for (;;) {
		knc_fullread(ctx, &byte, 1);
		knc_fullread(ctx, &offset, 4);
		knc_fullread(ctx, &len, 4);

		if (knc_error(ctx)) {
			fprintf(stderr, "S: knc_fullread: %s\n",
			    knc_errstr(ctx));
			exit(1);
		}

		if (knc_eof(ctx)) {
			fprintf(stderr, "S: got EOF exiting\n");
			break;
		}

#if 0
		while (len > 0) {
			char    buf[32768];
			int     ret;

			ret = knc_fullread(ctx, buf,
			    (sizeof(buf) < len)?sizeof(buf):len);

			if (knc_error(ctx)) {
				fprintf(stderr, "knc_read: %s\n",
					knc_errstr(ctx));
				exit(1);
			}

			len -= ret;    /* consuming input... */
		}
#else
		{
			size_t	 j;
			char	*buf;

			buf = malloc(len);
			if (!buf) {
				perror("malloc");
				exit(1);
			}
			knc_fullread(ctx, buf, len);

			for (j=0; j < len; j++)
				if (buf[j] != (char)(j & 0xff))
					fprintf(stderr, "Validate fails: "
					    "%zu: %d != %zu\n", j,
					    buf[j], (j & 0xff));

			free(buf);
		}
#endif

		byte = 0;
		knc_write(ctx, &byte, 1);
	}

	knc_close(ctx);
	knc_ctx_destroy(ctx);
	return 0;
}

int
runclient(int fd, const char *hostservice)
{
	knc_ctx ctx;
	int	i;

	fprintf(stderr, "C: pid == %d\n", getpid());

	no_sigpipe(fd);

	ctx = knc_ctx_init();

	knc_set_debug(ctx, debug);
	knc_set_debug_prefix(ctx, "C");
	knc_import_set_hb_service(ctx, hostservice, NULL);
	knc_give_net_fd(ctx, fd);
	knc_initiate(ctx);

	knc_authenticate(ctx);

	if (knc_error(ctx)) {
		fprintf(stderr, "C: knc_authenticate: %s\n", knc_errstr(ctx));
		exit(1);
	}

	for (i=0; i < 256; i++) {
		uint32_t	 offset;
		uint32_t	 len;
		size_t		 j;
		int		 ret;
		char		 byte;
		char		*buf;

		if (knc_error(ctx)) {
			fprintf(stderr, "C: %s\n", knc_errstr(ctx));
			break;
		}

		if (knc_eof(ctx)) {
			fprintf(stderr, "C: other end closed\n");
			break;
		}

		offset = random() % 140000;
		len    = random() %  70000;

		if (!quiet)
			fprintf(stderr, "C: Sending blob %d of len %u\n",
			    i, len);

		knc_write(ctx, &byte, 1);
		knc_write(ctx, &offset, 4);
		knc_write(ctx, &len, 4);

		buf = malloc(len);
		if (!buf) {
			perror("C: malloc");
			exit(1);
		}

		for (j=0; j < len; j++)
			buf[j] = j & 0xff;

		knc_write(ctx, buf, len);

		free(buf);

		knc_flush(ctx, KNC_DIR_SEND, -1);

		ret = knc_fullread(ctx, &byte, 1);

		if (ret != 1)
			fprintf(stderr, "C: knc_fullread() = %d: %s\n", ret,
			    strerror(errno));
	}

	knc_close(ctx);
	knc_ctx_destroy(ctx);
	return 0;
}
