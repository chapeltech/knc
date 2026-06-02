/* $Id$ */

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

#ifndef _KNC_H_
#define _KNC_H_

#define MAXADDRSIZ	128
#define MAXPORTSIZ	16

/* Global app preferences */
typedef struct prefs_s {
	char *			progname;	/* argv[0] */
	char			is_inetd;
	char			is_listener;
	char			is_wait_service;
	int			so_keepalive;
	int			no_half_close;
	int			noprivacy;
	int			num_children_max;
	int			max_connections;
	int			max_time;
	char			use_dns;
	char			no_fork;
	int			debug_level;
	char *			bindaddr;
	char *			sun_path;	/* optional path to socket */
	char *			sprinc;		/* service princ on other end */
	char *			prog;		/* program to exec */
	char *			syslog_ident;	/* syslog ident to use */
	int			network_fd;	/* wrap around existing fd */
	struct sockaddr_in	addr;
} prefs_t;

extern prefs_t prefs;

/* Connection specific data */
typedef struct work_s {
	/* The other side of our connection */
	int			network_family;
	char 			network_addr[MAXADDRSIZ];
	char 			network_port[MAXPORTSIZ];

	/* stderr of local side */
	int			local_err;

	char *			credentials;
	char *			export_name;
	char *			mech;
} work_t;

const char *vlog(const char *, ...);

/* pre: 0 <= level <= 7 */
#define LOG(level, fmt)							\
do {									\
	if ((level) <= prefs.debug_level) {				\
		vlog fmt;						\
									\
		syslog((level), "%s: %s", __func__, _log_buff);	\
		fprintf(stderr, "%s[%d]: ", prefs.progname,		\
			(int)getpid());					\
		fprintf(stderr, "%s: %s\n", __func__, _log_buff);	\
	}								\
} while(0)

#define LOG_ERRNO(level, fmt)						\
do {									\
	LOG((level), fmt);						\
	LOG((level), ("\terrno: %d (%s)", errno, strerror(errno)));	\
} while(0)

#endif /* _KNC_H_ */
