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
#include <limits.h>
#include <netdb.h>
#include <poll.h>
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
#include <libknc.h>
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
int	launch_program(knc_ctx, work_t *, int, char **);
int	prep_inetd(void);
int	do_inetd(int, char **);
int	do_inetd_wait(int, char **);
int	do_listener_inet(int, char **);
int	do_listener(int, int, char **);
int	do_unix_socket(knc_ctx);
int	fork_and_do_unix_socket(work_t *, int, int);
int	do_client(int, char **);
int	send_creds(knc_ctx, int, const char *const, const char * const);
int	emit_key_value(int, const char * const, const char * const);
int	setenv_knc_key_value(const char * const, const char * const);
int	do_work(knc_ctx, work_t *, int, char **);
int	fork_and_do_work(work_t *, int, int, int, char **);
void	work_init(work_t *);
void	work_free(work_t *);
int	shutdown_or_close(int, int);
int	nonblocking_set(int);
int	nonblocking_clr(int);
void	sockaddr_2str(work_t *, const struct sockaddr *, socklen_t);
static knc_ctx	 app_ctx_init(void);
static char	*app_display_name(gss_name_t);
static char	*app_export_name(gss_name_t);
static gss_OID	 app_mech_from_name(const char *);
static char	*app_mech_name(gss_OID);
static int	 app_oid_equal(gss_OID, gss_OID);
static char	*app_oid_to_hex(gss_OID);
static int	 attach_local_fds(knc_ctx, int, int);
static int	 attach_net_fd(knc_ctx, int, int);
static int	 authenticate(knc_ctx);
static int	 authenticate_client(knc_ctx);
static int	 authenticate_server(knc_ctx, work_t *);
static int	 configure_network(knc_ctx, int);
static int	 close_net_fds(knc_ctx);
static int	 log_stderr(work_t *);
static int	 parse_client_target(const char *, char **, char **);
static ssize_t	 write_full(int, const void *, size_t);

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
	const char	*value;
	char		*end;
	long		 seconds;

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

	if (!strncmp(opt, "handshake-timeout=",
	    strlen("handshake-timeout="))) {
		value = opt + strlen("handshake-timeout=");
		errno = 0;
		seconds = strtol(value, &end, 10);
		if (errno != 0 || *value == '\0' || *end != '\0' || seconds < 1 ||
		    seconds > INT_MAX / 1000) {
			fprintf(stderr, "option \"-o %s\" requires a positive "
			    "number of seconds\n", "handshake-timeout=");
			usage(prognam);
			exit(1);
		}
		prefs.handshake_timeout = (int)seconds;
		return;
	}

	if (!strcmp(opt, "lz4") || !strcmp(opt, "compress-lz4")) {
		prefs.compress_lz4 = 1;
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
	fprintf(stderr, "\t-o lz4\t\tenable LZ4 compression\n");
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
	prefs.handshake_timeout = 60;
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
			global_mech = app_mech_from_name(optarg);
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

static char *
app_buf_to_hex(const void *buf, size_t len)
{
	const unsigned char	*bufp = buf;
	unsigned char		 nibble;
	char			*ret;
	size_t			 i;
	size_t			 k;

	if (buf == NULL)
		return xstrdup("");

	ret = malloc(len * 2 + 1);
	if (!ret) {
		LOG(LOG_ERR, ("unable to malloc"));
		return NULL;
	}

	for (i = 0, k = 0; i < len; i++) {
		nibble = bufp[i] >> 4;
		ret[k++] = "0123456789ABCDEF"[nibble];
		nibble = bufp[i] & 0x0f;
		ret[k++] = "0123456789ABCDEF"[nibble];
	}

	ret[k] = '\0';
	return ret;
}

static char *
app_oid_to_hex(gss_OID oid)
{

	if (oid == GSS_C_NO_OID || oid->elements == NULL)
		return xstrdup("");

	return app_buf_to_hex(oid->elements, oid->length);
}

#define KNC_KRB5_MECH_OID "\052\206\110\206\367\022\001\002\002"

static gss_OID_desc krb5_mech_oid = {
	sizeof(KNC_KRB5_MECH_OID) - 1,
	(void *)KNC_KRB5_MECH_OID
};

static int
app_oid_equal(gss_OID a, gss_OID b)
{

	return a != GSS_C_NO_OID && b != GSS_C_NO_OID &&
	    a->length == b->length &&
	    memcmp(a->elements, b->elements, a->length) == 0;
}

static gss_OID
app_mech_from_name(const char *name)
{

	if (name == NULL || *name == '\0')
		return GSS_C_NO_OID;

#ifdef HAVE_GSS_NAME_TO_OID
	{
		gss_OID	oid;

		oid = gss_name_to_oid(name);
		if (oid != GSS_C_NO_OID)
			return oid;
	}
#endif

	if (strcasecmp(name, "krb5") == 0 ||
	    strcasecmp(name, "kerberos") == 0 ||
	    strcasecmp(name, "kerberos5") == 0)
		return &krb5_mech_oid;

	return GSS_C_NO_OID;
}

static char *
app_mech_name(gss_OID mech_oid)
{
	char	*ret;

	if (app_oid_equal(mech_oid, &krb5_mech_oid))
		return xstrdup("krb5");

#ifdef HAVE_GSS_OID_TO_NAME
	{
		const char *name = gss_oid_to_name(mech_oid);

		if (name != NULL)
			return xstrdup(name);
	}
#endif

	ret = app_oid_to_hex(mech_oid);
	if (!ret)
		LOG(LOG_ERR, ("unable to malloc"));
	return ret;
}

static char *
app_display_name(gss_name_t name)
{
	gss_buffer_desc	 buf;
	OM_uint32	 maj;
	OM_uint32	 min;
	char		*ret;

	if (name == GSS_C_NO_NAME)
		return NULL;

	maj = gss_display_name(&min, name, &buf, NULL);
	if (GSS_ERROR(maj)) {
		LOG(LOG_ERR, ("gss_display_name failed"));
		return NULL;
	}

	ret = malloc(buf.length + 1);
	if (ret == NULL) {
		LOG(LOG_ERR, ("unable to malloc"));
		gss_release_buffer(&min, &buf);
		return NULL;
	}

	memcpy(ret, buf.value, buf.length);
	ret[buf.length] = '\0';

	gss_release_buffer(&min, &buf);
	return ret;
}

static char *
app_export_name(gss_name_t name)
{
	gss_buffer_desc	 buf;
	OM_uint32	 maj;
	OM_uint32	 min;
	char		*ret;

	if (name == GSS_C_NO_NAME)
		return NULL;

	maj = gss_export_name(&min, name, &buf);
	if (GSS_ERROR(maj)) {
		LOG(LOG_ERR, ("gss_export_name failed"));
		return NULL;
	}

	ret = app_buf_to_hex(buf.value, buf.length);
	gss_release_buffer(&min, &buf);
	return ret;
}

static int
configure_network(knc_ctx ctx, int linger)
{
	struct linger	l;
	int		fd;

	fd = knc_get_net_wfd(ctx);
	if (fd == -1)
		fd = knc_get_net_rfd(ctx);
	if (fd == -1) {
		LOG(LOG_ERR, ("network fd was not initialised"));
		return 0;
	}

	if (linger) {
		l.l_onoff = 1;
		l.l_linger = 10;
		if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l)) < 0) {
			LOG_ERRNO(LOG_ERR, ("unable to set SO_LINGER on "
			    "network socket"));
			return 0;
		}
	}

	if (prefs.so_keepalive) {
		int	keepalive = 1;

		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
			       sizeof(keepalive)) < 0) {
			LOG_ERRNO(LOG_ERR, ("unable to set SO_KEEPALIVE on "
			    "network socket"));
		}
	}

	return 1;
}

static knc_ctx
app_ctx_init(void)
{
	knc_ctx	ctx;

	ctx = knc_ctx_init();
	if (ctx == NULL)
		return NULL;

	knc_set_opt(ctx, KNC_OPT_NOPRIVACY, prefs.noprivacy);
	knc_set_opt(ctx, KNC_OPT_NO_HALF_CLOSE, prefs.no_half_close);
	knc_set_opt(ctx, KNC_OPT_COMPRESS_LZ4, prefs.compress_lz4);
	knc_set_debug(ctx, prefs.debug_level >= LOG_DEBUG);
	knc_set_req_mech(ctx, global_mech);

	return ctx;
}

static int
attach_net_fd(knc_ctx ctx, int fd, int linger)
{

	knc_give_net_fd(ctx, fd);
	if (!configure_network(ctx, linger))
		return 0;
	knc_set_opt(ctx, KNC_SOCK_NONBLOCK, 1);
	return 1;
}

static int
authenticate(knc_ctx ctx)
{
	knc_callback	 cbs[4];
	struct pollfd	 fds[4];
	struct timespec	 deadline;
	struct timespec	 now;
	nfds_t		 nfds;
	long		 seconds;
	long		 nanoseconds;
	int		 ret;
	int		 timeout;

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) < 0) {
		LOG_ERRNO(LOG_ERR, ("unable to set authentication deadline"));
		return 0;
	}
	deadline.tv_sec += prefs.handshake_timeout;

	while (!knc_is_authenticated(ctx) && !knc_error(ctx)) {
		nfds = knc_get_pollfds(ctx, fds, cbs, 4);
		if (nfds == (nfds_t)-1) {
			LOG(LOG_ERR, ("knc_get_pollfds failed during handshake"));
			return 0;
		}

		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
			LOG_ERRNO(LOG_ERR,
			    ("unable to check authentication deadline"));
			return 0;
		}

		seconds = deadline.tv_sec - now.tv_sec;
		nanoseconds = deadline.tv_nsec - now.tv_nsec;
		if (nanoseconds < 0) {
			seconds--;
			nanoseconds += 1000000000L;
		}
		if (seconds < 0 || (seconds == 0 && nanoseconds == 0)) {
			LOG(LOG_ERR, ("authentication timed out after %d seconds",
			    prefs.handshake_timeout));
			return 0;
		}

		timeout = (int)(seconds * 1000 +
		    (nanoseconds + 999999L) / 1000000L);
		ret = poll(fds, nfds, timeout);
		if (ret < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			LOG_ERRNO(LOG_ERR, ("poll failed during handshake"));
			return 0;
		}
		if (ret == 0) {
			LOG(LOG_ERR, ("authentication timed out after %d seconds",
			    prefs.handshake_timeout));
			return 0;
		}

		knc_service_pollfds(ctx, fds, cbs, nfds);
		knc_garbage_collect(ctx);
	}

	return knc_is_authenticated(ctx) && !knc_error(ctx);
}

static int
authenticate_client(knc_ctx ctx)
{

	knc_set_opt(ctx, KNC_SOCK_NONBLOCK, 1);
	if (!authenticate(ctx)) {
		LOG(LOG_ERR, ("handshake with peer failed: %s",
		    knc_errstr(ctx)));
		return 0;
	}

	return 1;
}

static int
authenticate_server(knc_ctx ctx, work_t *work)
{
	gss_name_t	client;

	knc_accept(ctx);
	if (!authenticate(ctx)) {
		LOG(LOG_ERR, ("handshake with peer failed: %s",
		    knc_errstr(ctx)));
		return 0;
	}

	client = knc_get_client(ctx);
	work->credentials = app_display_name(client);
	work->export_name = app_export_name(client);
	work->mech = app_mech_name(knc_get_ret_mech(ctx));
	if (!work->credentials || !work->export_name || !work->mech)
		return 0;

	return 1;
}

#ifndef USE_LIBKNC
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

	if (len < 0) {
		if (errno == EINTR || errno == EAGAIN) {
			/*
			 * Non-blocking socket not ready.  Leave the buffer
			 * unchanged and return positive so move_data does
			 * not treat this as EPIPE (which is return 0).
			 */
			return 1;
		}
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
		}
		LOG_ERRNO(LOG_ERR, ("write_local_buffer, "
				    "write failed"));
		return -1;
	}

	/* Only advance on successful write of one or more bytes */
	if (len == 0)
		return 1;

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

		{
			int	 conf_state = 0;
			int	 privacy = prefs.noprivacy ? 0 : 1;

			maj = gss_wrap(&min, tok->gstd_ctx, privacy,
			    GSS_C_QOP_DEFAULT, &in, &conf_state, &out);
			GSTD_GSS_ERROR(maj, min, -1, "gss_wrap");

			if (privacy && !conf_state) {
				LOG(LOG_ERR, ("gss_wrap did not provide "
					      "confidentiality"));
				gss_release_buffer(&min, &out);
				return -1;
			}
		}

		if (out.length > sizeof(work->network_buffer.out) - 4) {
			LOG(LOG_ERR, ("gss_wrap output too large (%ld)",
				      (long)out.length));
			gss_release_buffer(&min, &out);
			return -1;
		}

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

	if (len < 0) {
		if (errno == EINTR || errno == EAGAIN) {
			/*
			 * Non-blocking socket not ready.  Leave the buffer
			 * unchanged and return positive so move_data does
			 * not treat this as EPIPE (which is return 0).
			 */
			return 1;
		}
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
		}
		LOG_ERRNO(LOG_ERR, ("write_network_buffer, "
				    "write failed"));
		return -1;
	}

	/* Only advance on successful write of one or more bytes */
	if (len == 0)
		return 1;

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
#endif

#define MAX(a,b)	(((a) > (b)) ? (a) : (b))

int
move_data(knc_ctx ctx, work_t *work)
{
#ifdef USE_LIBKNC
	knc_callback	 cbs[5];
	struct pollfd	 fds[5];
	nfds_t		 knc_nfds;
	nfds_t		 nfds;
	int		 ret;
	int		 stderr_idx = -1;

	while (!knc_io_complete(ctx) && !knc_error(ctx)) {
		stderr_idx = -1;
		knc_nfds = knc_get_pollfds(ctx, fds, cbs, 4);
		if (knc_nfds == (nfds_t)-1) {
			LOG(LOG_ERR, ("knc_get_pollfds failed"));
			return 0;
		}
		nfds = knc_nfds;

		if (work->local_err != -1 && nfds < 5) {
			stderr_idx = (int)nfds;
			fds[nfds].fd = work->local_err;
			fds[nfds].events = POLLIN;
			fds[nfds].revents = 0;
			nfds++;
		}

		if (reap() > 0)
			LOG(LOG_NOTICE, ("child died before EOF"));

		ret = poll(fds, nfds, 30000);
		if (ret < 0) {
			if (errno != EINTR && errno != EAGAIN) {
				LOG_ERRNO(LOG_ERR, ("poll failure"));
				return 0;
			}
			continue;
		}

		if (ret == 0) {
			knc_garbage_collect(ctx);
			continue;
		}

		if (stderr_idx != -1 &&
		    (fds[stderr_idx].revents & (POLLIN|POLLHUP|POLLERR)))
			log_stderr(work);

		knc_service_pollfds(ctx, fds, cbs, knc_nfds);
		knc_garbage_collect(ctx);
	}

	if (knc_error(ctx)) {
		LOG(LOG_ERR, ("KNC error: %s", knc_errstr(ctx)));
		return 0;
	}

	return 1;
#else
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
#endif
}

static int
attach_local_fds(knc_ctx ctx, int local_in, int local_out)
{

	if (local_in == -1 || local_out == -1) {
		LOG(LOG_ERR, ("local fds were not initialised"));
		return 0;
	}

	if (nonblocking_set(local_in) < 0) {
		LOG_ERRNO(LOG_ERR, ("unable to set O_NONBLOCK on local"
		    " read socket"));
		return 0;
	}

	if (local_out != local_in && nonblocking_set(local_out) < 0) {
		LOG_ERRNO(LOG_ERR, ("unable to set O_NONBLOCK on local"
		    " write socket"));
		return 0;
	}

	if (local_in == STDIN_FILENO || local_out == STDOUT_FILENO) {
		knc_set_local_fds(ctx, local_in, local_out);
		return 1;
	}

	if (local_in == local_out) {
		knc_give_local_fd(ctx, local_in);
		return 1;
	}

	knc_give_local_fds(ctx, local_in, local_out);
	return 1;
}

static int
close_net_fds(knc_ctx ctx)
{
	int	rfd;
	int	wfd;

	rfd = knc_get_net_rfd(ctx);
	wfd = knc_get_net_wfd(ctx);

	if (wfd != -1 && wfd != rfd)
		close(wfd);
	if (rfd != -1)
		close(rfd);

	return 1;
}

static int
log_stderr(work_t *work)
{
	char	errbuf[8192];
	int	ret;

	ret = read(work->local_err, errbuf, sizeof(errbuf) - 1);
	switch (ret) {
	case 0:
		/*FALLTHROUGH*/
	case -1:
		close(work->local_err);
		work->local_err = -1;
		return 1;
	default:
		errbuf[ret] = 0;
		LOG(LOG_ERR, ("stderr: %s", errbuf));
		return 1;
	}
}

int
send_creds(knc_ctx ctx, int local, const char *const key,
	   const char *const value)
{
	int	fd;

	if (local) {
		fd = knc_get_local_wfd(ctx);
		if (fd == -1) {
			LOG(LOG_ERR, ("local write fd was not initialised"));
			return 0;
		}

		if (!value)
			return write_full(fd, "END\n", 4) < 0 ? 0 : 1;

		return emit_key_value(fd, key, value);
	}

	if (!value)
		return 1;

	return setenv_knc_key_value(key, value);
}

int
emit_key_value(int fd, const char * const key,
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
	if ((write_full(fd, key, strlen(key)) < 0) ||
	    (write_full(fd, ":", 1) <  0) ||
	    (write_full(fd, value, strlen(value)) < 0) ||
	    (write_full(fd, "\n", 1) < 0)) {
		LOG_ERRNO(LOG_ERR, ("failed to write KEY:VALUE pair "
				    "'%s:%s'.  connection terminated.",
				    key, value));
		return 0;
	}

	return 1;
}

int
setenv_knc_key_value(const char * const key, const char * const value)
{
	char	*name;
	int	 ret;

	if ((name = malloc(strlen(key) + sizeof("KNC_"))) == NULL) {
		LOG(LOG_ERR, ("malloc failure during setenv_knc_key_value"));
		return 0;
	}

	sprintf(name, "KNC_%s", key);
	if (value)
		ret = setenv(name, value, 1);
	else
		ret = unsetenv(name);
	free(name);

	if (ret < 0) {
		LOG_ERRNO(LOG_ERR, ("unable to update KNC environment"));
		return 0;
	}

	return 1;
}

static ssize_t
write_full(int fd, const void *buf, size_t len)
{
	const char	*p = buf;
	size_t		 nleft = len;
	ssize_t		 nwritten;

	while (nleft > 0) {
		nwritten = write(fd, p, nleft);
		if (nwritten < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			LOG_ERRNO(LOG_ERR, ("write failed"));
			return -1;
		}
		nleft -= (size_t)nwritten;
		p += nwritten;
	}

	LOG(LOG_DEBUG, ("wrote %zu bytes", len));
	return (ssize_t)len;
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
do_work(knc_ctx ctx, work_t *work, int argc, char **argv)
{
	int		ret = 0;
	int		local = 0;

	if (!authenticate_server(ctx, work)) {
		LOG(LOG_ERR, ("handshake with peer failed"));
		goto out;
	}

	/* Now we have credentials */
	LOG(LOG_DEBUG, ("[%s] authenticated", work->credentials));

	local = !(prefs.sun_path == NULL);

	if (local) {
		if (!do_unix_socket(ctx))
			goto out;
	} else {
		/*
		 * Environment variables must be populated before exec.
		 */
		if (!(send_creds(ctx, local, "MECH", work->mech)	&&
		      (strcmp(work->mech, "krb5") != 0			||
		       send_creds(ctx, local, "CREDS",
		       work->credentials))				&&
		      send_creds(ctx, local, "EXPORT_NAME",
		       work->export_name)				&&
		      (work->network_family != AF_INET			||
		       send_creds(ctx, local, "REMOTE_IP",
		       work->network_addr))				&&
		      (work->network_family != AF_INET6			||
		       send_creds(ctx, local, "REMOTE_IP6",
		       work->network_addr))				&&
		      send_creds(ctx, local, "REMOTE_ADDR",
		       work->network_addr)				&&
		      send_creds(ctx, local, "REMOTE_PORT",
		       work->network_port)				&&
		      send_creds(ctx, local, "VERSION",
		       KNC_VERSION_STRING)				&&
		      send_creds(ctx, local, "END", NULL))) {
			LOG(LOG_ERR, ("Failed to propagate creds.  connection "
				      "terminated."));
			goto out;
		}

		/* Handle the non-Unix-domain-socket case. */
		if (argc == 0) {
			if (!attach_local_fds(ctx, STDOUT_FILENO, STDIN_FILENO))
				goto out;
		} else if (!launch_program(ctx, work, argc, argv))
			goto out;
	}

	if (local) {
		if (!(send_creds(ctx, local, "MECH", work->mech)	&&
		      (strcmp(work->mech, "krb5") != 0			||
		       send_creds(ctx, local, "CREDS",
		       work->credentials))				&&
		      send_creds(ctx, local, "EXPORT_NAME",
		       work->export_name)				&&
		      (work->network_family != AF_INET			||
		       send_creds(ctx, local, "REMOTE_IP",
		       work->network_addr))				&&
		      (work->network_family != AF_INET6			||
		       send_creds(ctx, local, "REMOTE_IP6",
		       work->network_addr))				&&
		      send_creds(ctx, local, "REMOTE_ADDR",
		       work->network_addr)				&&
		      send_creds(ctx, local, "REMOTE_PORT",
		       work->network_port)				&&
		      send_creds(ctx, local, "VERSION",
		       KNC_VERSION_STRING)				&&
		      send_creds(ctx, local, "END", NULL))) {
			LOG(LOG_ERR, ("Failed to propagate creds.  connection "
				      "terminated."));
			goto out;
		}
	}

	ret = move_data(ctx, work);

out:
	if (work->local_err != -1) {
		close(work->local_err);
		work->local_err = -1;
	}
	knc_ctx_destroy(ctx);

	return ret;
}

int
launch_program(knc_ctx ctx, work_t *work, int argc, char **argv)
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

		close_net_fds(ctx);
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
			_exit(1);
		}

		if (dup2(stdout_fds[1], STDOUT_FILENO) < 0) {
			LOG_ERRNO(LOG_ERR, ("STDOUT_FILENO dup2 failed"));
			close(stdin_fds[1]);
			close(stdout_fds[1]);
			close(prog_err[1]);
			_exit(1);
		}

		close(stdin_fds[1]);
		close(stdout_fds[1]);

		if (dup2(prog_err[1], STDERR_FILENO) < 0) {
			LOG_ERRNO(LOG_ERR, ("STDERR_FILENO dup2 failed"));
			close(prog_err[1]);
			_exit(1);
		}

		close(prog_err[1]);

		sig_set(SIGPIPE, SIG_DFL, 0);

		execv(argv[0], argv);

		/* If we get here, the exec failed */

		LOG_ERRNO(LOG_ERR, ("exec of %s failed", argv[0]));
		_exit(1);
	}

	/* parent */

	close(stdin_fds[1]);
	close(stdout_fds[1]);
	close(prog_err[1]);
	if (!attach_local_fds(ctx, stdout_fds[0], stdin_fds[0])) {
		close(stdin_fds[0]);
		close(stdout_fds[0]);
		close(prog_err[0]);
		return 0;
	}
	work->local_err = prog_err[0];
	return 1;
}

int
fork_and_do_work(work_t *work, int listener, int fd, int argc, char **argv)
{
	knc_ctx	ctx;
	pid_t	pid;

	pid = fork();

	if (pid == -1) {
		LOG_ERRNO(LOG_CRIT, ("unable to fork to service connection"));
		return 0;
	} else if (pid == 0) {
		/* child */
		close(listener);
		ctx = app_ctx_init();
		if (ctx == NULL || !attach_net_fd(ctx, fd, 1))
			exit(1);
		exit(!do_work(ctx, work, argc, argv));
	}

	LOG(LOG_DEBUG, ("parent returning to accept"));
	return 1;
}

int
do_unix_socket(knc_ctx ctx)
{
	int			fd;
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

	if (!attach_local_fds(ctx, fd, fd)) {
		close(fd);
		return 0;
	}

	return 1;
}

int
fork_and_do_unix_socket(work_t *work, int listener, int fd)
{
	knc_ctx	ctx;
	pid_t	pid;

	pid = fork();

	if (pid == -1) {
		LOG_ERRNO(LOG_CRIT, ("unable to fork to service connection"));
		return 0;
	} else if (pid == 0) {
		/* child */
		close(listener);
		ctx = app_ctx_init();
		if (ctx == NULL || !attach_net_fd(ctx, fd, 1))
			exit(1);
		exit(!do_work(ctx, work, 0, NULL));
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
	knc_ctx			ctx;
 
	work_init(&work);

	fd = prep_inetd();
	if (fd == -1)
		return 0;

	/* Obtain the remote TCP info */
	len = sizeof(ss);
	ret = getpeername(fd, (struct sockaddr *)&ss, &len);
	if (ret == -1) {
		LOG(LOG_ERR, ("getpeername: %s", strerror(errno)));
	} else {
		sockaddr_2str(&work, (struct sockaddr *)&ss, len);
	}

	ctx = app_ctx_init();
	if (ctx == NULL) {
		close(fd);
		work_free(&work);
		return 0;
	}
	if (!attach_net_fd(ctx, fd, 1)) {
		knc_ctx_destroy(ctx);
		work_free(&work);
		return 0;
	}

	ret = do_work(ctx, &work, argc, argv);

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
	knc_ctx			 ctx;

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

		if (prefs.sun_path != NULL) {
			/* Connecting to a unix domain socket */
			if (prefs.no_fork) {
				ctx = app_ctx_init();
				if (ctx != NULL && attach_net_fd(ctx, fd, 1))
					do_work(ctx, work, 0, NULL);
				else if (ctx != NULL)
					knc_ctx_destroy(ctx);
				else
					close(fd);
			} else if (fork_and_do_unix_socket(work, listener, fd)) {
				++num_children;
				close(fd);
			} else {
				close(fd);
			}
		} else {
			/* execing a program */
			if (prefs.no_fork) {
				ctx = app_ctx_init();
				if (ctx != NULL && attach_net_fd(ctx, fd, 1))
					do_work(ctx, work, argc, argv);
				else if (ctx != NULL)
					knc_ctx_destroy(ctx);
				else
					close(fd);
			} else if (fork_and_do_work(work, listener, fd, argc, argv)) {
				++num_children;
				close(fd);
			} else {
				close(fd);
			}
		}

		/* The parent no longer needs this work structure. */
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

static int
parse_client_target(const char *target, char **servicep, char **hostp)
{
	char	*buf;
	char	*host;
	char	*port;

	buf = xstrdup(target);
	host = index(buf, '@');
	if (host == NULL) {
		LOG(LOG_ERR, ("invalid service@host: %s", target));
		free(buf);
		return 0;
	}

	*host++ = '\0';
	port = index(host, ':');
	if (port)
		*port = '\0';

	*servicep = buf;
	*hostp = host;
	return 1;
}

int
do_client(int argc, char **argv)
{
	char			*service;
	char			*port;
	char			*hostname;
	int			 ret;
	work_t			 work;
	knc_ctx			 ctx;

	work_init(&work);

	if (!parse_client_target(argv[0], &service, &hostname))
		return 0;

	port = argv[1];
	ctx = app_ctx_init();
	if (ctx == NULL) {
		free(service);
		return 0;
	}

	if (prefs.sprinc)
		knc_import_set_service(ctx, prefs.sprinc, GSS_C_NO_OID);

	if (prefs.network_fd != -1) {
		LOG(LOG_DEBUG, ("wrapping existing fd %d", prefs.network_fd));
		if (!prefs.sprinc)
			knc_import_set_hb_service(ctx, hostname, service);
		if (!attach_net_fd(ctx, prefs.network_fd, 0)) {
			free(service);
			knc_ctx_destroy(ctx);
			return 0;
		}
		knc_initiate(ctx);
	} else {
		ctx = knc_connect(ctx, argv[0], "host", port, 0);
		if (knc_error(ctx)) {
			LOG(LOG_ERR, ("connect failed: %s", knc_errstr(ctx)));
			free(service);
			knc_ctx_destroy(ctx);
			return 0;
		}
		if (!configure_network(ctx, 0)) {
			free(service);
			knc_ctx_destroy(ctx);
			return 0;
		}
		knc_set_opt(ctx, KNC_SOCK_NONBLOCK, 1);
	}

	free(service);

	if (!authenticate_client(ctx)) {
		work_free(&work);
		knc_ctx_destroy(ctx);
		return 0;
	}

	if (!attach_local_fds(ctx, STDIN_FILENO, STDOUT_FILENO)) {
		work_free(&work);
		knc_ctx_destroy(ctx);
		return 0;
	}

	ret = move_data(ctx, &work);

	knc_ctx_destroy(ctx);
	work_free(&work);

	return ret;
}

void
work_init(work_t *work)
{

	memset(work, 0, sizeof(work_t));

	work->local_err = -1;
}

void
work_free(work_t *work)
{

	free(work->credentials);
	work->credentials = NULL;
	free(work->export_name);
	work->export_name = NULL;
	free(work->mech);
	work->mech = NULL;
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
