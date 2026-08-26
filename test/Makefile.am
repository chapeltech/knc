# $Id$

AM_CPPFLAGS = -I$(top_srcdir)/lib $(WFLAGS) $(GSSAPI_CFLAGS)
LDADD = ../lib/libknc.la

bin_PROGRAMS = unit unit-simple testknc servefile
check_PROGRAMS = unit-stream unit-pollfds unit-eof
TEST_EXTENSIONS = .py
PY_LOG_COMPILER = python3
TESTS_ENVIRONMENT = KNC=$(abs_top_builddir)/bin/knc
TESTS = unit-stream unit-pollfds unit-eof knc-handshake-timeout.py

unit_stream_SOURCES = unit-stream.c
unit_stream_LDADD = $(GSSAPI_LIBS)
unit_pollfds_LDADD = $(GSSAPI_LIBS)
unit_eof_LDADD = $(GSSAPI_LIBS)

EXTRA_DIST = knc-exec-tests.py knc-bench.py knc-handshake-timeout.py
KNC_EXEC_TEST_ARGS =
KNC_BENCH_ARGS =

.PHONY: check-knc-exec
check-knc-exec:
	python3 $(srcdir)/knc-exec-tests.py --knc $(top_builddir)/bin/knc $(KNC_EXEC_TEST_ARGS)

.PHONY: bench-knc
bench-knc:
	LD_LIBRARY_PATH=$(top_builddir)/lib/.libs$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}} \
	    python3 $(srcdir)/knc-bench.py --old-knc /usr/local/bin/knc --new-knc $(top_builddir)/bin/.libs/knc $(KNC_BENCH_ARGS)
