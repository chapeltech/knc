/* $Id: knc.c,v 1.13 2008/11/25 22:01:18 dowdes Exp $ */

/*-
 * Copyright 2009  Morgan Stanley and Co. Incorporated
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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "gssstdio.h"
#include "knc.h"

prefs_t prefs;

/* BEGIN_DECLS */

void	sig_handler(int);
void	usage(const char *);
int	do_bind_addr(const char *, struct sockaddr_in *);
int	setup_listener(unsigned short int);
int	connect_host(const char *, const char *);
int	connect_host_dosrv(const char *, const char *);
int	connect_host_inner(const char *, const char *);
int	reap(void);
int	getport(const char *, const char *);
int	launch_program(work_t *, int, char **);
int	prep_inetd(void);
int	do_inetd(int, char **);
int	do_inetd_wait(int, char **);
int	do_listener_inet(int, char **);
int	do_listener(int, int, char **);
int	do_unix_socket(work_t *);
int	fork_and_do_unix_socket(work_t *, int);
int	do_client(int, char **);
int	send_creds(int, work_t *, const char *const, const char * const);
int	emit_key_value(work_t *, const char * const, const char * const);
int	putenv_knc_key_value(const char * const, const char * const);
int	do_work(work_t *, int, char **);
int	fork_and_do_work(work_t *, int, int, char **);
int	move_local_to_network_buffer(work_t *);
int	move_network_to_local_buffer(work_t *);
void	write_buffer_init(write_buffer_t *);
void	work_init(work_t *);
void	work_free(work_t *);
int	shutdown_or_close(int, int);
int	nonblocking_set(int);
int	nonblocking_clr(int);
void	sockaddr_2str(work_t *, const struct sockaddr *, socklen_t);

/* END_DECLS */

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

/* Look Ma, no threading */
char _log_buff[2048];

/*
 * global variables
 */

gss_OID global_mech = GSS_C_NO_OID;

const char *
vlog(const char *fmt, ...)
{
	va_list	ap;
	va_start(ap, fmt);

	vsnprintf(_log_buff, sizeof(_log_buff), fmt, ap);

	return _log_buff;
}

int dienow = 0;

void
sig_handler(int signum)
{

	switch (signum) {
	case SIGHUP:
		dienow = 1;
		break;
	default:
		break;
	}

	/* do_listener() will handle the actual reaping. */
	return;
}

void
sig_set(int signum, void (*f)(int), int cldstop)
{
	struct sigaction	 sa;
	sigset_t		 sigset;
	const char		*err = NULL;
	const char		*sig;

	if (!err && f == SIG_IGN)
		err = "ignore";
	if (!err && f == SIG_DFL)
		err = "reset";
	if (!err)
		err = "install";

	switch (signum) {
	case SIGCHLD:	sig = "SIGCHLD";	break;
	case SIGPIPE:	sig = "SIGPIPE";	break;
	default:	sig = "unknown";	break;
	}

	sigemptyset(&sigset);
	sa.sa_handler = f;
	sa.sa_mask = sigset;
	sa.sa_flags = cldstop ? SA_NOCLDSTOP : 0;
	if (sigaction(signum, &sa, NULL) < 0)
		LOG_ERRNO(LOG_WARNING, ("failed to %s %s (%d)", err, sig,
		    signum));
}

void
log_reap_status(pid_t pid, int status)
{
	if (WIFSIGNALED(status)) {
		LOG(LOG_WARNING, ("child pid %d killed by signal %d",
				  (int)pid, WTERMSIG(status)));
#ifdef WCOREDUMP
		if (WCOREDUMP(status))
			LOG(LOG_WARNING, (" (core dumped)"));
#endif /* WCOREDUMP */
	} else
		LOG(LOG_NOTICE, ("child pid %d exited with status %d",
				 (int)pid, WEXITSTATUS(status)));
}

int
reap(void)
{
	pid_t	pid;
	int	status;
	int	num_reaped = 0;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		++num_reaped;
		log_reap_status(pid, status);
	}

	return num_reaped;
}

int
getport(const char *servnam, const char *proto)
{
	struct servent	*sv;
	int		 port;

	sv = getservbyname(servnam, proto);
	if (sv)
		return sv->s_port;

	port = atoi(servnam);
	return htons(port);
}

int
shutdown_or_close(int fd, int how)
{
	int ret;

	if ((ret = shutdown(fd, how)) == -1)
		return close(fd);

	return ret;
}

int
sleep_reap(void)
{
	pid_t	pid;
	int	status;

	/* Wait for a child to die */
	if ((pid = wait(&status)) > 0) {
		log_reap_status(pid, status);
		/* Check to see if more than one have passed on... */
		return reap() + 1;
	}

	return 0;
}

char *
xstrdup(const char *orig)
{
	char *s = strdup(orig);
	if (!s) {
		fprintf(stderr, "%s\n", strerror(errno));
		exit(1);
	}
	return s;
}

void
parse_opt(const char *prognam, const char *opt)
{

	if (!strcmp(opt, "keepalive")) {
		prefs.so_keepalive = 1;
		return;
	}

	if (!strcmp(opt, "no-half-close")) {
		prefs.no_half_close = 1;
		return;
	}

	if (!strcmp(opt, "noprivacy")) {
		prefs.noprivacy = 1;
		return;
	}

	if (!strcmp(opt, "noprivate")) {
		prefs.noprivacy = 1;
		return;
	}

	if (!strncmp(opt, "syslog-ident=", strlen("syslog-ident="))) {
		opt += strlen("syslog-ident=");
		if (!*opt) {
			fprintf(stderr, "option \"-o %s\" requires a value\n",
			    "syslog-ident=");
			usage(prognam);
			exit(1);
		}
		prefs.syslog_ident = xstrdup(opt);
		return;
	}

	fprintf(stderr, "option \"-o %s\" unrecognised.\n", opt);
	usage(prognam);
	exit(1);
}

void
usage(const char *progname)
{

	fprintf(stderr, "usage:\n");
	fprintf(stderr, "  server: %s -l [opts] <port> "
		"prog [args]\n", progname);
	fprintf(stderr, "  server: %s -il [opts] <prog> [args]\n", progname);
	fprintf(stderr, "  server: %s -lS <path> [opts] <port>\n", progname);
	fprintf(stderr, "  server: %s -ilS <path>\n", progname);
	fprintf(stderr, "  client: %s [opts] <service>@<host> <port>\n",
		progname);
	fprintf(stderr, "  client: %s [opts] -N<fd> <service>@<host>\n\n",
		progname);
	fprintf(stderr, "\t-a <bindaddr>\tbind to address <bindaddr>\n");
	fprintf(stderr, "\t-c <num>\tin listener mode, limit the number "
		"of children to <num>\n");
	fprintf(stderr, "\t-d\t\tincrement debug level\n");
	fprintf(stderr, "\t-f\t\tin listener mode, don't fork after accept\n");
	fprintf(stderr, "\t\t\tuseful for debugging\n");
	fprintf(stderr, "\t-i\t\tset ``inetd''mode\n");
	fprintf(stderr, "\t-l\t\tlistener (server) mode\n");
	fprintf(stderr, "\t-n\t\tno DNS\n");
	fprintf(stderr, "\t-w\t\tset ``inetd wait'' mode\n");
	fprintf(stderr, "\t-M <num>\tin server mode, maximum number of "
		"connexions to process\n");
	fprintf(stderr, "\t-N <num>\tuse fd <num> as network file "
		"descriptor (in client mode)\n");
	fprintf(stderr, "\t-P <sprinc>\tin client mode specify Kerberos "
		"principal for server\n");
	fprintf(stderr, "\t-S <path>\tconnect to Unix domain socket "
		"(server mode)\n");
	fprintf(stderr, "\t-T <max_time>\tIn server mode, maximum time to "
		"process requests\n");
	fprintf(stderr, "\t-?\t\tthis usage\n");
}

int
main(int argc, char **argv)
{
	int	c;
	int	ret;

	/* initialize preferences */
	memset(&prefs, 0, sizeof(prefs));	/* not strictly necessary... */
	prefs.use_dns = 1;
	prefs.debug_level = LOG_INFO;		/* display LOG_INFO and worse */
	prefs.num_children_max = 128;
	prefs.progname = xstrdup(argv[0]);	/* facilitate stderr logs */
	prefs.network_fd = -1;			/* wrap connection around
						   existing socket */

	/* process arguments */
	while ((c = getopt(argc, argv, POS "linda:?m:fc:o:wM:N:P:S:T:")) != -1) {
		switch (c) {
		case 'l':
			prefs.is_listener = 1;
			break;
		case 'i':
			/* inetd implies listener */
			prefs.is_listener = 1;
			prefs.is_inetd = 1;
			break;
		case 'n':
			prefs.use_dns = 0;
			break;
		case 'd':
			++prefs.debug_level;
			break;
		case 'a':
			if (optarg != NULL) {
				prefs.bindaddr = xstrdup(optarg);
			} else {
				LOG(LOG_ERR, ("-a requires an address\n"));
				exit(1);
			}
			break;
		case 'm':
			global_mech = gstd_mech_from_name(optarg);
			if (!global_mech) {
				fprintf(stderr, "Invalid mech \"%s\".\n", optarg);
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'f':
			prefs.no_fork = 1;
			break;
		case 'c':
			if (optarg != NULL) {
				prefs.num_children_max = atoi(optarg);
			} else {
				LOG(LOG_ERR, ("-c requires an integer\n"));
				exit(1);
			}
			break;
		case 'o':
			parse_opt(argv[0], optarg);
			break;
		case 'w':
			/* inetd wait service implies inetd and listener */
			prefs.is_listener = 1;
			prefs.is_inetd = 1;
			prefs.is_wait_service = 1;
			break;
		case 'M':
			if (optarg != NULL) {
				prefs.max_connections = atoi(optarg);
			} else {
				LOG(LOG_ERR, ("-M requires an integer\n"));
				exit(1);
			}
			break;
		case 'N':
			if (optarg != NULL) {
				prefs.network_fd = atoi(optarg);
			} else {
				LOG(LOG_ERR, ("-N requires an integer\n"));
				exit(1);
			}
			break;
		case 'P':
			if (optarg != NULL) {
				prefs.sprinc = xstrdup(optarg);
			} else {
				LOG(LOG_ERR, ("-P requires an service "
				    "principal\n"));
				exit(1);
			}
			break;
		case 'S':
			if (optarg != NULL) {
				prefs.sun_path = xstrdup(optarg);
			} else {
				LOG(LOG_ERR, ("-S requires an address\n"));
				exit(1);
			}
			break;
		case 'T':
			if (optarg != NULL) {
				prefs.max_time = atoi(optarg);
			} else {
				LOG(LOG_ERR, ("-T requires an integer\n"));
				exit(1);
			}
			break;
		case '?':
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (prefs.syslog_ident != NULL)
		openlog(prefs.syslog_ident, LOG_PID, LOG_DAEMON);
	else
		openlog(prefs.progname, LOG_PID, LOG_DAEMON);

	if (prefs.is_listener && prefs.network_fd != -1)
		prefs.is_inetd = 1;

	if (prefs.no_fork && !prefs.is_listener) {
		LOG(LOG_ERR, ("-f only makes sense with -l\n"));
		exit(1);
	}

	if (prefs.sun_path != NULL && !prefs.is_listener) {
		LOG(LOG_ERR, ("-S only makes sense with -l\n"));
		exit(1);
	}

	/* adjust number of remaining arguments */
	argc -= optind;

	/* Non-inetd listener requires <service> <port> and optional prog
	   inetd listener requires <service> and optional prog
	   client requires <service>[@<host>], <host> and <port> */
	if (prefs.sun_path) {
		/* ==> prefs.is_listener */
		if ((prefs.is_inetd && (argc != 0)) ||
		    (!prefs.is_inetd && (argc != 1))) {
			usage(argv[0]);
			exit(1);
		}
	} else {
		/* !prefs.sun_path ==> not connecting to Unix domain */
		if (prefs.is_listener) {
			if ((!prefs.is_inetd && (argc < 2)) ||
			    (prefs.is_inetd && (argc < 1))) {
				usage(argv[0]);
				exit(1);
			}
		} else {
			/* !prefs.is_listener ==> client */
			if (((prefs.network_fd != -1) && (argc != 1)) ||
			    ((prefs.network_fd == -1) && (argc != 1) &&
			     (argc != 2) && (argc != 3))) {
				usage(argv[0]);
				exit(1);
			}
		}
	}

	/* Initialize address */
	prefs.addr.sin_addr.s_addr = htonl(INADDR_ANY);

	/* If we've specified a bind address ... */
	if (prefs.bindaddr != NULL) {
		if (!prefs.is_listener) {
			fprintf(stderr, "-a only makes sense with -l\n");
			exit(1);
		}

		if (prefs.is_inetd) {
			fprintf(stderr, "-a doesn't work in inetd mode\n");
			exit(1);
		}

		if (!do_bind_addr(prefs.bindaddr, &prefs.addr))
			exit(1);
	}

	/* And now the meat of the app */
	if (prefs.is_inetd)
		exit(!do_inetd(argc, argv + optind));

	if (prefs.is_listener)
		exit(!do_listener_inet(argc, argv + optind));

	exit(!do_client(argc, argv + optind));
}

extern int h_errno;

#if defined(MY_SOLARIS)
#	define my_hstrerror(e)	internal_hstrerror((e))
#else
#	define my_hstrerror(e)	hstrerror((e))
#endif

const char *
internal_hstrerror(int e)
{

	switch (e) {
	case NETDB_INTERNAL:
		return "Internal resolver library error";
	case HOST_NOT_FOUND:
		return "Host not found";
	case TRY_AGAIN:
		return "Try again";
	case NO_RECOVERY:
		return "No recovery";
	case NO_DATA:
		return "No data / NXDOMAIN";
	default:
		return "Unknown error";
	}
}

int
connect_host(const char *domain, const char *service)
{

	/*
	 * if getaddrinfo does not do SRV records, then we must
	 * unfortunately special case them.  We use libroken for
	 * this.  Otherwise just call the inner function.
	 */
#if 0	/* XXXrcd: not yet, not yet */
	return connect_host_dosrv(domain, service);
#else
	return connect_host_inner(domain, service);
#endif
}

#if 0	/* XXXrcd: not yet, not yet */
#define PORTSTRLEN	32

int
connect_host_dosrv(const char *domain, const char *service)
{
	struct resource_record	*rr;
	struct dns_reply	*r;
	char			 portstr[PORTSTRLEN];
	char			*qdomain;
	int			 fd;

	asprintf(&qdomain, "_%s._tcp%s%s", service, *domain?".":"", domain);
	LOG(LOG_DEBUG, ("connect_host_dosrv looking up %s", qdomain));
	r = dns_lookup(qdomain, "SRV");
	free(qdomain);
	if (!r)
		return connect_host_inner(domain, service);

	dns_srv_order(r);

	for (rr = r->head; rr; rr = rr->next) {
		if (rr->type != T_SRV)
			continue;
		snprintf(portstr, PORTSTRLEN, "%u", rr->u.srv->port);
		fd = connect_host_inner(rr->u.srv->target, portstr);
		if (fd != -1)
			break;
	}
	dns_free_data(r);
	return fd;
}

#undef PORTSTRLEN
#endif

int
connect_host_inner(const char *domain, const char *service)
{
	struct addrinfo	 ai;
	struct addrinfo	*res;
	struct addrinfo	*res0;
	int		 ret;
	int		 s = -1;
	char		 buf[256];

	LOG(LOG_DEBUG, ("connecting to (%s, %s)", service, domain));
	if (!service) {
		LOG(LOG_ERR, ("Failed to provide port\n"));
		return -1;
	}

	memset(&ai, 0x0, sizeof(ai));
	ai.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(domain, service, &ai, &res0);
	if (ret) {
		LOG(LOG_ERR, ("getaddrinfo: (%s,%s) %s", domain, service,
		    gai_strerror(ret)));
		return -1;
	}
	for (res=res0; res; res=res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1) {
			LOG(LOG_ERR, ("connect: %s", strerror(errno)));
			continue;
		}
		ret = connect(s, res->ai_addr, res->ai_addrlen);
		if (ret != -1)
			break;
		close(s);
		s = -1;
		LOG(LOG_ERR, ("connect: %s", strerror(errno)));
	}
	return s;
}

int
do_bind_addr(const char *s, struct sockaddr_in *sa)
{
	struct hostent	*h;

	/*
	 * We first check if we've been given a dotted quad.  If this
	 * should fail, and we're allowed to use DNS, we'll use gethostbyname
	 * to look up our host.
	 *
	 * Of course, gethostbyname, givn a dotted quad, will return success,
	 * and populate the name field with the given address, but it will not
	 * properly populate the rest of the hostent structure, including
	 * the h_addr_list.
	 */
#if defined(MY_SOLARIS)
	if ((sa->sin_addr.s_addr = inet_addr(s)) != -1)
		return 1;
#else
	if (inet_aton(s, &sa->sin_addr))
		return 1;
#endif

	if (prefs.use_dns) {
		if ((h = gethostbyname(s)) == NULL) {
			LOG(LOG_ERR, ("gethostbyname failed: %s (h_error=%d)",
				      my_hstrerror(h_errno), h_errno));
			return 0;
		} else {
			memcpy(&(sa->sin_addr), h->h_addr_list[0],
			       (size_t)h->h_length);

			return 1;
		}
	} else {
		LOG(LOG_ERR, ("address '%s' must be dotted-quad when -n is in"
			      " effect", s));
		return 0;
	}

	return 0;
}

int
setup_listener(unsigned short int port)
{
	int	fd;
	int	opt;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to create socket"));
		return -1;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to set FD_CLOEXEC on listener"));
		close(fd);
		return -1;
	}

	/* Set REUSEADDR (so we avoid waiting out TIME_WAIT) */
	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		LOG_ERRNO(LOG_ERR, ("unable to set SO_REUSEADDR on listener"
				    " socket"));
		close(fd);
		return -1;
	}

	/* Our prefs.addr address already has the the s_addr parameter
	   set up */
	prefs.addr.sin_family = AF_INET;
	prefs.addr.sin_port = port;

	if (bind(fd, (struct sockaddr *)&prefs.addr, sizeof(prefs.addr)) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to bind listening socket"));
		close(fd);
		return -1;
	}

	if (listen(fd, 5) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to listen on socket"));
		close(fd);
		return -1;
	}

	return fd;
}

int
handshake(work_t *work)
{

	if (prefs.is_listener) {
		if ((work->context = gstd_accept(work->network_fd,
					 &work->credentials,
					 &work->export_name,
					 &work->mech)) == NULL)
			return 0;
		else
			return 1;
	} else {
		if ((work->context = gstd_initiate(work->hostname,
						   work->service,
						   work->sprinc,
						   work->network_fd)) == NULL)
			return 0;
		else
			return 1;
	}

	/* NOTREACHED */
	return 0;
}

int
move_network_to_local_buffer(work_t *work)
{

	/* We should NOT be called if we've already buffered inbound data */
	if (work->local_buffer.in_valid) {
		LOG(LOG_ERR, ("local_buffer already has buffered inbound"
			      " data"));
		return -1;
	}

	work->local_buffer.in_len = gstd_read(work->context,
					work->local_buffer.in,
					sizeof(work->local_buffer.in));

	switch (work->local_buffer.in_len) {
	case 0:
		/* EOF */
		return 0;
	case -1:
		LOG(LOG_ERR, ("gstd_read error"));
		return -1;
	case -2:
		return 1;
	}

	work->local_buffer.in_valid = 1;
	return work->local_buffer.in_len;
}

int
move_local_to_network_buffer(work_t *work)
{

	/* We should NOT be called if we've already buffered inbound data */
	if (work->network_buffer.in_valid) {
		LOG(LOG_ERR, ("network_buffer already has buffered inbound"
			      " data"));
		return -1;
	}

	work->network_buffer.in_len = read(work->local_in,
					   work->network_buffer.in,
					   sizeof(work->network_buffer.in));
	if (work->network_buffer.in_len == 0) {
		/* EOF */
		return 0;
	} else if (work->network_buffer.in_len < 0) {
		if (errno == ECONNRESET)
			return 0; /* Treat as EOF */

		LOG_ERRNO(LOG_ERR, ("local read failed"));
		return -1;
	}

	work->network_buffer.in_valid = 1;
	return work->network_buffer.in_len;
}

/*
 * Returns:
 *		1	Buffer completely transmitted
 *		0	Buffer partially transmitted, please call again
 *		-1	Unrecoverable error
 */
int
write_local_buffer(work_t *work)
{
	int	len;

	if (!work->local_buffer.out_valid) {
		if (!work->local_buffer.in_valid) {
			LOG(LOG_ERR, ("no valid data to write"));
			return -1;
		}

		/* We have some new data to transmit */

		if (work->local_buffer.in_len <= 0) {
			LOG(LOG_ERR, ("non-positive input buffer length (%d)",
				      work->local_buffer.in_len));
			return -1;
		}

		memcpy(&(work->local_buffer.out[0]),
		       &(work->local_buffer.in[0]),
		       work->local_buffer.in_len);

		work->local_buffer.out_valid = 1;
		work->local_buffer.out_len = work->local_buffer.in_len;
		work->local_buffer.out_pos = 0;
		work->local_buffer.in_valid = 0;
	}

	/* the "out" portion of our buffer is now properly set up */
	len = write(work->local_out,
		    &(work->local_buffer.out[work->local_buffer.out_pos]),
		    work->local_buffer.out_len);

	if (len < 0 && ((errno != EINTR) && (errno != EAGAIN))) {
		if (errno == EPIPE) {
			/*
			 * It's possible that exec'd programs (or the
			 * parent of the the client) has exited before
			 * data could be received from the network
			 * side (destined for the entity which has
			 * exited).  In this case (since we're
			 * ignoring SIGPIPE), the write will fail with
			 * EPIPE.  We propagate this condition out of
			 * of this function by returning 0, which is
			 * turned in to an appropriate EOF to the opposite
			 * end of the connection.
			 *
			 * In this case, we must consider the buffer
			 * transmitted as well.
			 */
			LOG(LOG_DEBUG, ("write got EPIPE"));

			work->local_buffer.out_valid = 0;
			return 0;
		} else {
			LOG_ERRNO(LOG_ERR, ("write_local_buffer, "
					    "write failed"));
			return -1;
		}
	}


	work->local_buffer.out_len -= len;
	LOG(LOG_DEBUG, ("transmitted %d bytes, %d remaining", len,
			work->local_buffer.out_len));

	/* Does that finish off the buffer? */
	if (work->local_buffer.out_len == 0) {
		work->local_buffer.out_valid = 0;
		return 1;
	}

	work->local_buffer.out_pos += len;
	return len;
}

/*
 * Returns:
 *		1	Buffer completely transmitted
 *		0	Buffer partially transmitted, please call again
 *		-1	Unrecoverable error
 */
int
write_network_buffer(work_t *work)
{
	int		 len;
	unsigned long	 packet_len;
	gss_buffer_desc	 in;
	gss_buffer_desc	 out;
	OM_uint32	 maj;
	OM_uint32	 min;
	struct gstd_tok	*tok = work->context;

	if (!work->network_buffer.out_valid) {
		if (!work->network_buffer.in_valid) {
			LOG(LOG_ERR, ("no valid data to write"));
			return -1;
		}

		/* We have some new data to encrypt and transmit */

		if (work->network_buffer.in_len <= 0) {
			LOG(LOG_ERR, ("non-positive input buffer length (%d)",
				      work->network_buffer.in_len));
			return -1;
		}

		if (work->network_buffer.in_len > GSTD_MAXPACKETCONTENTS) {
			LOG(LOG_ERR, ("input buffer length too large (%d)",
				      work->network_buffer.in_len));
			return -1;
		}

		/* Encrypt */
		in.length = work->network_buffer.in_len;
		in.value  = (void *)work->network_buffer.in;

		LOG(LOG_DEBUG, ("plaintext of length %ld", (long)in.length));

		maj = gss_wrap(&min, tok->gstd_ctx, prefs.noprivacy?0:1,
			       GSS_C_QOP_DEFAULT, &in, NULL, &out);
		GSTD_GSS_ERROR(maj, min, -1, "gss_wrap");

		memcpy(&(work->network_buffer.out[4]), out.value, out.length);
		packet_len = htonl(out.length);
		memcpy(&(work->network_buffer.out[0]), &packet_len, 4);

		LOG(LOG_DEBUG, ("ciphertext of length %ld", (long)out.length));

		work->network_buffer.out_valid = 1;
		work->network_buffer.out_len = out.length + 4;
		work->network_buffer.out_pos = 0;
		work->network_buffer.in_valid = 0;

		gss_release_buffer(&min, &out);
	}

	/* the "out" portion of our buffer is now properly set up */
	len = write(work->network_fd,
		    &(work->network_buffer.out[work->network_buffer.out_pos]),
		    work->network_buffer.out_len);

	if (len < 0 && ((errno != EINTR) && (errno != EAGAIN))) {
		if (errno == EPIPE) {
			/*
			 * It's possible that exec'd programs (or the
			 * parent of the the client) has exited before
			 * data could be received from the network
			 * side (destined for the entity which has
			 * exited).  In this case (since we're
			 * ignoring SIGPIPE), the write will fail with
			 * EPIPE.    We propagate this condition out of
			 * of this function by returning 0, which is
			 * turned in to an appropriate EOF to the opposite
			 * end of the connection.
			 *
			 * In this case, we must consider the buffer
			 * transmitted as well.
			 */
			LOG(LOG_DEBUG, ("gstd_write got EPIPE"));

			work->network_buffer.out_valid = 0;
			return 0;
		} else {
			LOG_ERRNO(LOG_ERR, ("write_network_buffer, "
					    "write failed"));
			return -1;
		}
	}



	work->network_buffer.out_len -= len;
	LOG(LOG_DEBUG, ("transmitted %d bytes, %d remaining", len,
			work->network_buffer.out_len));

	/* Does that finish off the buffer? */
	if (work->network_buffer.out_len == 0) {
		work->network_buffer.out_valid = 0;
		return 1;
	}

	work->network_buffer.out_pos += len;
	return len;
}

#define MAX(a,b)	(((a) > (b)) ? (a) : (b))

int
move_data(work_t *work)
{
	int		ret;
	int		mret;
	int		select_is_the_worst_api_ever;
	fd_set		rdset;
	fd_set		wrset;
	char		local_active = 1;
	char		network_active = 1;
	char		shut_nread_lwrite = 0;
	char		shut_nwrite_lread = 0;
	struct timeval	tv;
	char		errbuf[8192];

	work->local_buffer.in_valid = 0;
	work->local_buffer.out_valid = 0;

	work->network_buffer.out_valid = 0;
	work->network_buffer.in_valid = 0;

	if (work->local_err != -1) {
		select_is_the_worst_api_ever =
		    MAX(work->network_fd,
			MAX(work->local_err, MAX(work->local_in,
						 work->local_out)));
	} else {
		select_is_the_worst_api_ever =
		    MAX(work->network_fd,
			MAX(work->local_in, work->local_out));
	}

	nonblocking_set(work->network_fd);
	nonblocking_set(work->local_in);
	nonblocking_set(work->local_out);

	do {
		if ((shut_nread_lwrite == 1) &&
		    !work->local_buffer.in_valid &&
		    !work->local_buffer.out_valid) {
			LOG(LOG_DEBUG, ("Calling shutdown on network side "
					"read and local side write."));
			shutdown_or_close(work->network_fd, SHUT_RD);
			shutdown_or_close(work->local_out, SHUT_WR);
			++shut_nread_lwrite;
		}

		if ((shut_nwrite_lread == 1) &&
		    !work->network_buffer.in_valid &&
		    !work->network_buffer.out_valid) {
			LOG(LOG_DEBUG, ("Calling shutdown on network side "
				       "write and local side read"));
			shutdown_or_close(work->network_fd, SHUT_WR);
			shutdown_or_close(work->local_in, SHUT_RD);
			++shut_nwrite_lread;
		}

		/*
		 * Now here we may have received SIGCHLD.
		 * (it's possible we have no child, of course,
		 * but then what would we be doing here?)
		 *
		 * Once we've drained any communication coming *from*
		 * the child (local_active == 0 *and*
		 * work->network_buffer.out_valid == 0), then
		 * those facts, in combination with with a dead child
		 * means we should exit.
		 */
		if (reap() > 0)
			LOG(LOG_NOTICE, ("child died before EOF"));

		FD_ZERO(&rdset);
		FD_ZERO(&wrset);

		/* Add stderr */
		if (work->local_err != -1)
			FD_SET(work->local_err, &rdset);

		/*
		 * We have this timeout only to allow us to recover
		 * from children which prematurely exit
		 */
		tv.tv_sec = 30;
		tv.tv_usec = 0;

		/* Read Side */
		if (network_active && !work->local_buffer.in_valid) {
			FD_SET(work->network_fd, &rdset);
		}

		if (local_active && !work->network_buffer.in_valid) {
			FD_SET(work->local_in, &rdset);
		}

		/* Write Side */
		if (work->local_buffer.in_valid ||
		    work->local_buffer.out_valid) {
			FD_SET(work->local_out, &wrset);
		}

		if (work->network_buffer.in_valid ||
		    work->network_buffer.out_valid) {
			FD_SET(work->network_fd, &wrset);
		}

		ret = select(select_is_the_worst_api_ever + 1,
			     &rdset, &wrset, NULL, &tv);

		/*
		 * As we read from the local and network sides of the
		 * connection, we must be mindful that we are responsible
		 * for _passing on_ EOF conditions in each direction.
		 * That is to say, should we receive an EOF from the network
		 * we must cause one to appear on the reading side of our
		 * subordinate.  We use shutdown() to accomplish this.
		 * In particular, since some of our connections may be
		 * file-based descriptors, we use shutdown_or_close() which
		 * first attempts a half-close, and if that fails, tries
		 * a full close.
		 *
		 * Additionally, we must continue to shuffle data from the
		 * remaining side, until it too disappears (and we pass that
		 * fact on as well).
		 *
		 * Moreover, we must simulate back pressure on the sockets.
		 * If we have already read some data which has yet to be
		 * delivered to the opposite end, we must stop reading
		 * further data.  In reality we have a double-buffer system
		 * which allows us to move one encrypted packet from
		 * the "in" side of the buffer to the "out" side, from which
		 * we deliver data to the opposite end.  This lets us read
		 * 2 encrypted packets from the sending side before pressure
		 * is applied.
		 *
		 * The buffers may be confusingly named.  The "network_buffer"
		 * is data waiting to be transmitted to the "network" side.
		 * Similarly, the "local_buffer" is data waiting to be
		 * trasmitted to the "local" side.
		 */

		/* At least one descriptor ready for reading... */
		if (ret > 0) {
			/* Something happened on stderr, better log it */
			if ((work->local_err != -1) &&
			    FD_ISSET(work->local_err, &rdset)) {
				mret = read(work->local_err, errbuf,
					    sizeof(errbuf) - 1);
				switch (mret) {
				case 0:
					/*FALLTHROUGH*/
				case -1:
					/* just close it on errors or EOF. */
					close(work->local_err);
					work->local_err = -1;
					break;
				default:
					errbuf[mret] = 0;
					LOG(LOG_ERR, ("stderr: %s", errbuf));
				}
			}

			/* The network has something to say */
			if (FD_ISSET(work->network_fd, &rdset)) {
				mret = move_network_to_local_buffer(work);
				if (mret == 0) {
					LOG(LOG_DEBUG, ("EOF on network side."
						        " Queueing shutdown"));

					shut_nread_lwrite = 1;

					network_active = 0;

					if (prefs.no_half_close) {
						shut_nwrite_lread = 1;
						local_active = 0;
					}
				} else if (mret < 0)
					return 0;
			}

			/* Our local side has something to say */
			if (FD_ISSET(work->local_in, &rdset)) {
				mret = move_local_to_network_buffer(work);
				if (mret == 0) {
					LOG(LOG_DEBUG, ("EOF on local-side "
						        "read. Queueing "
						        "shutdown"));

					shut_nwrite_lread = 1;

					local_active = 0;

					if (prefs.no_half_close) {
						shut_nread_lwrite = 1;
						network_active = 0;
					}
				} else if (mret < 0)
					return 0;
			}

			/*
			 * We have something to say to the network and it's
			 * listening.
			 */

			if (FD_ISSET(work->network_fd, &wrset) &&
			    (work->network_buffer.out_valid ||
			     work->network_buffer.in_valid)) {
				mret = write_network_buffer(work);
				if (mret < 0)
					/* Error other than EPIPE */
					return 0;
				else if (mret == 0) {
					/* Got EPIPE */
					LOG(LOG_DEBUG, ("EPIPE on network-side "
						        "write. Queueing "
						        "shutdown"));
					shut_nwrite_lread = 1;
				}
			}

			/*
			 * We have something to say to the local side and it's
			 * listening.
			 */
			if (FD_ISSET(work->local_out, &wrset) &&
			    (work->local_buffer.out_valid ||
			     work->local_buffer.in_valid)) {
				mret = write_local_buffer(work);
				if (mret < 0)
					/* Error other than EPIPE */
					return 0;
				else if (mret == 0) {
					/* Got EPIPE */
					LOG(LOG_DEBUG, ("EPIPE on local-side "
						        "write. Queueing "
						        "shutdown"));
					shut_nread_lwrite = 1;
				}
			}
		} else if (ret == 0) {
			/* NOP */
		} else {
			/* ret < 0 */
			if ((errno != EINTR) && (errno != EAGAIN)) {
				LOG_ERRNO(LOG_ERR, ("select failure"));
				return 0;
			}
		}
	} while (network_active || local_active ||
		 work->local_buffer.out_valid   ||
		 work->local_buffer.in_valid    ||
		 work->network_buffer.out_valid ||
		 work->network_buffer.in_valid);

	return 1;
}

int
send_creds(int local, work_t *work, const char *const key,
	   const char *const value)
{

	if (local && !value)
		return writen(work->local_out, "END\n", 4) < 0 ? 0 : 1;

	if (!value)
		return 1;

	if (local)
		return emit_key_value(work, key, value);

	return putenv_knc_key_value(key, value);
}

int
emit_key_value(work_t * work, const char * const key,
	       const char * const value)
{

	/*
	 * There are characters which can cause this protocol to be
	 * subverted.
	 *
	 * First, on the sender, embedded newlines mean you can inject your
	 * own key:value pair.
	 *
	 * On the receiver, poor data handling may allow embedded NULs
	 * to cause trouble.
	 *
	 * Disallow both.
	 */
	if (strpbrk(value, "\n\000") != NULL) {
		LOG(LOG_CRIT, ("embedded newline or NUL in value '%s' for key "
			       "'%s'.  connection terminated.", value, key));
		return 0;
	}

	/* Write KEY:VALUE pair */
	if ((writen(work->local_out, key, strlen(key)) < 0) ||
	    (writen(work->local_out, ":", 1) <  0) ||
	    (writen(work->local_out, value, strlen(value)) < 0) ||
	    (writen(work->local_out, "\n", 1) < 0)) {
		LOG_ERRNO(LOG_ERR, ("failed to write KEY:VALUE pair "
				    "'%s:%s'.  connection terminated.",
				    key, value));
		return 0;
	}

	return 1;
}

int
putenv_knc_key_value(const char * const key, const char * const value)
{
	char	*p;

	if ((p = malloc(strlen(key) + 1 + strlen(value) + 5)) == NULL) {
		LOG(LOG_ERR, ("malloc failure during putenv_knc_key_value"));
		return 0;
	}

	/* safe */
	sprintf(p, "KNC_%s=%s", key, value);
	putenv(p);

	return 1;
}

void
sockaddr_2str(work_t *work, const struct sockaddr *sa, socklen_t len)
{
	int	ret;

	work->network_family = sa->sa_family;
	ret = getnameinfo(sa, len,
	    work->network_addr, sizeof(work->network_addr),
	    work->network_port, sizeof(work->network_port),
	    NI_NUMERICHOST | NI_NUMERICSERV);

	if (ret) {
		LOG(LOG_ERR, ("Error converting incoming address into "
		    "a string: %s", gai_strerror(ret)));
		work->network_addr[0] = '\0';
		work->network_port[0] = '\0';
	}
}

int
do_work(work_t *work, int argc, char **argv)
{
	int		ret;
	struct linger	l;
	int		local = 0;

	/*
	 * We now have a socket (network_fd) and soon, a local descriptor --
	 * either from inetd or one side of a socketpair we created before
	 * exec()ing a program (local_fd)
	 *
	 * We must establish what the remote end's credentials are, and
	 * begin ferrying data to and fro.
	 */
	if (!handshake(work)) {
		LOG(LOG_ERR, ("handshake with peer failed"));
		return 0;
	}

	/* Ensure all messages are sent before close */
	l.l_onoff = 1;
	l.l_linger = 10;
	if (setsockopt(work->network_fd, SOL_SOCKET, SO_LINGER,
		       &l, sizeof(l)) < 0) {
		LOG_ERRNO(LOG_ERR, ("unable to set SO_LINGER on network"
				    " socket"));
		return 0;
	}

	/* Use non-blocking network I/O */
	if (nonblocking_set(work->network_fd) < 0) {
		LOG_ERRNO(LOG_ERR, ("unable to set O_NONBLOCK on network"
				    " socket"));
		return 0;
	}

	/* Optionally set keepalives */
	if (prefs.so_keepalive) {
		int	keepalive = 1;

		if (setsockopt(work->network_fd, SOL_SOCKET, SO_KEEPALIVE,
			       &keepalive, sizeof(keepalive)) < 0) {
			LOG_ERRNO(LOG_ERR, ("unable to set SO_KEEPALIVE on "
					    "network socket"));

			/* XXXrcd: We continue on failure */
		}
	}

	/* Now we have credentials */
	LOG(LOG_DEBUG, ("[%s] authenticated", work->credentials));

	local = !(prefs.sun_path == NULL);

	/* send the credentials to our daemon side */

	if (!(send_creds(local, work, "MECH", work->mech)		&&
	      (strcmp(work->mech, "krb5") != 0			||
	       send_creds(local, work, "CREDS", work->credentials))	&&
	      send_creds(local, work, "EXPORT_NAME", work->export_name)	&&
	      (work->network_family != AF_INET			||
	       send_creds(local, work, "REMOTE_IP", work->network_addr))&&
	      (work->network_family != AF_INET6			||
	       send_creds(local, work, "REMOTE_IP6", work->network_addr))&&
	      send_creds(local, work, "REMOTE_ADDR", work->network_addr)&&
	      send_creds(local, work, "REMOTE_PORT", work->network_port)&&
	      send_creds(local, work, "VERSION", KNC_VERSION_STRING)	&&
	      send_creds(local, work, "END", NULL))) {
		LOG(LOG_ERR, ("Failed to propagate creds.  connection "
			      "terminated."));
		return 0;
	}

	/* Handle the NON - Unix domain socket case */
	if (!local) {
		if (argc == 0) {
			work->local_in = STDOUT_FILENO;
			work->local_out = STDIN_FILENO;
		} else if (!launch_program(work, argc, argv))
			exit(1);
	}

	/* Use non-blocking local writes I/O */
	if (nonblocking_set(work->local_out) < 0) {
		LOG_ERRNO(LOG_ERR, ("unable to set O_NONBLOCK on local"
				    " write socket"));
		return 0;
	}

	ret = move_data(work);

	close(work->network_fd);
	close(work->local_in);
	close(work->local_out);
	close(work->local_err);

	return ret;
}

int
launch_program(work_t *work, int argc, char **argv)
{
	pid_t	pid;
	int	stdin_fds[2];
	int	stdout_fds[2];
	int	prog_err[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, stdin_fds) < 0) {
		LOG_ERRNO(LOG_ERR, ("socketpair for stdin failed"));
		return 0;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, stdout_fds) < 0) {
		LOG_ERRNO(LOG_ERR, ("socketpair for stdout failed"));
		close(stdin_fds[0]);
		close(stdin_fds[1]);
		return 0;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, prog_err) < 0) {
		LOG_ERRNO(LOG_ERR, ("socketpair for stderr failed"));
		close(stdin_fds[0]);
		close(stdin_fds[1]);
		close(stdout_fds[0]);
		close(stdout_fds[1]);
		return 0;
	}

	pid = fork();

	if (pid == -1) {
		LOG_ERRNO(LOG_CRIT, ("unable to fork to launch program"));
		close(stdin_fds[0]);
		close(stdin_fds[1]);
		close(stdout_fds[0]);
		close(stdout_fds[1]);
		close(prog_err[0]);
		close(prog_err[1]);
		return 0;
	}

	if (pid == 0) {
		/* child */

		close(work->network_fd);
		close(stdin_fds[0]);
		close(stdout_fds[0]);
		close(prog_err[0]);
		LOG(LOG_DEBUG, ("child process preparing to exec %s",
				argv[0]));

		if (dup2(stdin_fds[1], STDIN_FILENO) < 0) {
			LOG_ERRNO(LOG_ERR, ("STDIN_FILENO dup2 failed"));
			close(stdin_fds[1]);
			close(stdout_fds[1]);
			close(prog_err[1]);
			return 0;
		}

		if (dup2(stdout_fds[1], STDOUT_FILENO) < 0) {
			LOG_ERRNO(LOG_ERR, ("STDOUT_FILENO dup2 failed"));
			close(stdin_fds[1]);
			close(stdout_fds[1]);
			close(prog_err[1]);
			return 0;
		}

		close(stdin_fds[1]);
		close(stdout_fds[1]);

		if (dup2(prog_err[1], STDERR_FILENO) < 0) {
			LOG_ERRNO(LOG_ERR, ("STDERR_FILENO dup2 failed"));
			close(prog_err[1]);
			return 0;
		}

		close(prog_err[1]);

		sig_set(SIGPIPE, SIG_DFL, 0);

		execv(argv[0], argv);

		/* If we get here, the exec failed */

		LOG_ERRNO(LOG_ERR, ("exec of %s failed", argv[0]));
		exit(1);
	}

	/* parent */

	close(stdin_fds[1]);
	close(stdout_fds[1]);
	close(prog_err[1]);
	work->local_out = stdin_fds[0];
	work->local_in = stdout_fds[0];
	work->local_err = prog_err[0];
	return 1;
}

int
fork_and_do_work(work_t *work, int listener, int argc, char **argv)
{
	pid_t	pid;

	pid = fork();

	if (pid == -1) {
		LOG_ERRNO(LOG_CRIT, ("unable to fork to service connection"));
		return 0;
	} else if (pid == 0) {
		/* child */
		close(listener);
		exit(!do_work(work, argc, argv));
	}

	LOG(LOG_DEBUG, ("parent returning to accept"));
	return 1;
}

int
do_unix_socket(work_t *work)
{
	int			fd;
	int			ret;
	struct sockaddr_un	pfun;

	memset(&pfun, 0, sizeof(pfun));

	if (strlen(prefs.sun_path) > (sizeof(pfun.sun_path) - 1)) {
		LOG(LOG_ERR, ("Unix domain socket path length of %d exceeds "
			      "maximum allowed length of %d",
			      strlen(prefs.sun_path),
			      sizeof(pfun.sun_path) - 1));
		return 0;
	}

	/* safe to copy */
	strcpy(pfun.sun_path, prefs.sun_path);

	pfun.sun_family = PF_UNIX;

	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to create Unix domain socket"));
		return 0;
	}

#if defined(MY_SOLARIS)
	if (connect(fd, (struct sockaddr *)&pfun, sizeof(pfun)) < 0) {
#else
	if (connect(fd, (struct sockaddr *)&pfun, SUN_LEN(&pfun)) < 0) {
#endif
		LOG_ERRNO(LOG_ERR, ("failed to connect to %s", pfun.sun_path));
		close(fd);
		return 0;
	}

	work->local_in = work->local_out = fd;

	ret = do_work(work, 0, 0);

	close(work->local_in);
	close(work->local_out);
	close(work->network_fd);

	return ret;
}

int
fork_and_do_unix_socket(work_t *work, int listener)
{
	pid_t	pid;

	pid = fork();

	if (pid == -1) {
		LOG_ERRNO(LOG_CRIT, ("unable to fork to service connection"));
		return 0;
	} else if (pid == 0) {
		/* child */
		close(listener);
		exit(!do_unix_socket(work));
	}

	LOG(LOG_DEBUG, ("parent returning to accept"));
	return 1;
}

int
prep_inetd(void)
{
	int	net_fd = 0;
	int	fd;

	if (prefs.network_fd != -1)
		net_fd = prefs.network_fd;

	/* Move our network side to a higher fd */
	if (net_fd > STDERR_FILENO || (net_fd = dup(STDIN_FILENO)) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to dup stdin"));
		return -1;
	}

	/* Stop dumb libraries (and us) from printing to the network */
	if ((fd = open("/dev/null", O_RDWR)) < 0) {
		LOG_ERRNO(LOG_ERR, ("can't open /dev/null"));
		return -1;
	}

	if (dup2(fd, STDIN_FILENO) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to nullify STDIN_FILENO"));
		close(fd);
		return -1;
	}

	if (dup2(fd, STDOUT_FILENO) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to nullify STDOUT_FILENO"));
		close(fd);
		return -1;
	}

	if (dup2(fd, STDERR_FILENO) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to nullify STDERR_FILENO"));
		close(fd);
		return -1;
	}

	close(fd);
	return net_fd;
}

int
do_inetd_wait(int argc, char **argv)
{
	int	listener;

	listener = prep_inetd();
	return do_listener(listener, argc, argv);
}

int
do_inetd_nowait(int argc, char **argv)
{
	struct sockaddr_storage	ss;
	work_t			work;
	socklen_t               len;
	int			fd;
	int			ret;
 
	work_init(&work);

	work.network_fd = prep_inetd();
	if (work.network_fd == -1)
		return 0;

	/* Obtain the remote TCP info */
	len = sizeof(ss);
	ret = getpeername(work.network_fd, (struct sockaddr *)&ss, &len);
	if (ret == -1) {
		LOG(LOG_ERR, ("getpeername: %s", strerror(errno)));
	} else {
		sockaddr_2str(&work, (struct sockaddr *)&ss, len);
	}

	if (prefs.sun_path != NULL)
		ret = do_unix_socket(&work);
	else
		ret = do_work(&work, argc, argv);

	work_free(&work);

	return ret;
}

int
do_inetd(int argc, char **argv)
{
	socklen_t	len = sizeof(int);
	int		ret;
	int		val;

	if (prefs.is_wait_service)
		return do_inetd_wait(argc, argv);

	ret = getsockopt(prefs.network_fd == -1 ? 0 : prefs.network_fd,
	    SOL_SOCKET, SO_ACCEPTCONN, &val, &len);

	if (ret != -1 && val)
		return do_inetd_wait(argc, argv);

	return do_inetd_nowait(argc, argv);
}

int
do_listener_inet(int argc, char **argv)
{
	uint16_t	port;
	int		listener;

	/*
	 * If we haven't been launched from inetd, we'll need to do the usual
	 * listening/accepting, and fork to process an accepted connection
	 */
	port = getport(argv[0], "tcp");
	if ((listener = setup_listener(port)) < 0)
		return 0;

	return do_listener(listener, argc - 1, argv + 1);
}

int
do_listener(int listener, int argc, char **argv)
{
	struct sockaddr_storage	 sa;
	uint16_t		 port;
	int			 fd;
	int			 num_children = 0;
	int			 num_connections = 0;
	time_t			 endtime = 0;
	socklen_t		 client_len;
	work_t			*work;

	sig_set(SIGHUP, sig_handler, 1);
	sig_set(SIGCHLD, sig_handler, 1);
	sig_set(SIGPIPE, SIG_IGN, 0);

	if (prefs.max_time)
		endtime = time(NULL) + prefs.max_time;

	while (1) {
		/*
		 * If we have exceeded the maximum number of allowed
		 * child processes, we sleep here.
		 */
		while (num_children >= prefs.num_children_max) {
			LOG(LOG_DEBUG, ("maximum children exceeded, %d > %d",
					num_children, prefs.num_children_max));
			num_children -= sleep_reap();
		}

		/* Reap any children who've died */
		num_children -= reap();

		if ((work = (work_t *)malloc(sizeof(work_t))) == NULL) {
			LOG(LOG_CRIT, ("malloc of work structure failed"));
			return 0;
		}

		work_init(work);

		client_len = sizeof(sa);
		if ((fd = accept(listener, (struct sockaddr *)&sa,
				 &client_len)) < 0) {

			if ((errno != EINTR) && (errno != EAGAIN))
				LOG_ERRNO(LOG_WARNING, ("failed to accept"));

			work_free(work);
			free(work);

			continue;
		}

		sockaddr_2str(work, (struct sockaddr *)&sa, client_len);
		num_connections++;

		LOG(LOG_INFO, ("Accepted connection from %s port %s",
			       work->network_addr, work->network_port));

		work->network_fd = fd;

		if (prefs.sun_path != NULL) {
			/* Connecting to a unix domain socket */
			if (prefs.no_fork)
				do_unix_socket(work);
			else if (fork_and_do_unix_socket(work, listener))
				++num_children;
		} else {
			/* execing a program */
			if (prefs.no_fork)
				do_work(work, argc, argv);
			else if (fork_and_do_work(work, listener, argc, argv))
				++num_children;
		}

		/* And now, as the parent, we no longer need this work
		   structure or file descriptor */
		close(fd);
		work_free(work);
		free(work);

		/*
		 * If we've processed the maximum number of connections,
		 * or have exceeded our maximum time limit, we exit...
		 */
		if (prefs.max_connections &&
		    num_connections >= prefs.max_connections)
			break;

		if (endtime && time(NULL) > endtime)
			break;

		if (dienow)
			break;
	}

	return 0;
}

int
do_client(int argc, char **argv)
{
	char			*hostname;
	char			*service;
	char			*port;
	int			 fd;
	int			 ret;
	work_t			 work;
	struct sockaddr_in	 sa;

	memset(&sa, 0, sizeof(sa));
	work_init(&work);

	service = strdup(argv[0]);
	if (!service) {
		LOG(LOG_ERR, ("do_client: strdup failed, %s",
		    strerror(errno)));
		return 0;
	}

	/* Pick out the hostname portion of service@host */
	if ((hostname = (index(service, '@'))) == NULL) {
		    LOG(LOG_ERR, ("invalid service@host: %s", argv[0]));
		    free(service);
		    return 0;
	}

	*hostname++ = '\0';

	port = index(hostname, ':');
	if (port)
		*port++ = '\0';
	if (argv[1])
		port = argv[1];

	/*
	 * XXXrcd: for now, we default the port to be the service name,
	 *         but later we should put this logic in the SRV RR
	 *         handling code.  The idea will be: if the port isn't
	 *         provided, then look for the SRV RRs failing back to
	 *         use getaddrinfo(3) with service as the port.  If the
	 *         port is provided, then avoid the SRV RR lookup.
	 */

	if (!port)
		port = service;

	if (prefs.sprinc)
		work.sprinc = xstrdup(prefs.sprinc);

	work.local_in = STDIN_FILENO;
	work.local_out = STDOUT_FILENO;

	/* work.local_err = STDERR_FILENO;*/
	/* XXX - why doesn't this work for clients? */
	work.local_err = -1;

	if (prefs.network_fd != -1) {
		LOG(LOG_DEBUG, ("wrapping existing fd %d", prefs.network_fd));
		work.network_fd = prefs.network_fd;
	} else {
		fd = connect_host(hostname, port);

		if (fd == -1)
			exit(1);

		work.network_fd = fd;
	}

	/* Optionally set keepalives */
	if (prefs.so_keepalive) {
		int	keepalive = 1;

		if (setsockopt(work.network_fd, SOL_SOCKET, SO_KEEPALIVE,
			       &keepalive, sizeof(keepalive)) < 0) {
			LOG_ERRNO(LOG_ERR, ("unable to set SO_KEEPALIVE on "
					    "network socket"));

			/* XXXrcd: We continue on failure */
		}
	}

	work.hostname = xstrdup(hostname);
	work.service = xstrdup(service);
	free(service);

	if (!handshake(&work)) {
		work_free(&work);
		return 0;
	}

	ret = move_data(&work);

	work_free(&work);

	return ret;
}

void
work_init(work_t *work)
{

	memset(work, 0, sizeof(work_t));

	work->network_fd = -1;
	work->local_in = -1;
	work->local_out = -1;
	work->local_err = -1;
}

void
work_free(work_t *work)
{

	free(work->credentials);

	if (work->context != NULL)
		gstd_close(work->context);

	free(work->service);
	free(work->hostname);
	free(work->sprinc);
}

int
nonblocking_set(int fd)
{
	long	curflags;

	/*
	 * XXXrcd: lame hack for me.  don't set non-blocking on terminals
	 *         as this leaves my terminal in an annoying state...  This
	 *         should not be an issue for any protocols as they are not
	 *         generally run over terminals...
	 */
	if (isatty(fd))
		return 0;

	if ((curflags = fcntl(fd, F_GETFL)) < 0) {
		LOG_ERRNO(LOG_ERR, ("unable to get flags"));
		return -1;
	}

	curflags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, curflags) < 0) {
		LOG_ERRNO(LOG_ERR, ("unable to set O_NONBLOCK"));
		return -1;
	}

	return 0;
}

int
nonblocking_clr(int fd)
{
	long	curflags;

	if ((curflags = fcntl(fd, F_GETFL)) < 0)
		return -1;

	curflags &= ~O_NONBLOCK;

	if (fcntl(fd, F_SETFL, curflags) < 0)
		return -1;

	return 0;
}
