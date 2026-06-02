# $Id$

AM_CPPFLAGS = -I$(top_srcdir)/lib $(WFLAGS) $(GSSAPI_CFLAGS)
LDADD = ../lib/libknc.la

bin_PROGRAMS = unit unit-simple testknc servefile
check_PROGRAMS = unit-pollfds unit-eof
TESTS = unit-pollfds unit-eof

unit_pollfds_LDADD = $(GSSAPI_LIBS)
unit_eof_LDADD = $(GSSAPI_LIBS)

EXTRA_DIST = knc-exec-tests.py knc-bench.py
KNC_EXEC_TEST_ARGS =
KNC_BENCH_ARGS =

.PHONY: check-knc-exec
check-knc-exec:
	python3 $(srcdir)/knc-exec-tests.py --knc $(top_builddir)/bin/knc $(KNC_EXEC_TEST_ARGS)

.PHONY: bench-knc
bench-knc:
	python3 $(srcdir)/knc-bench.py --old-knc /usr/local/bin/knc --new-knc $(top_builddir)/bin/knc $(KNC_BENCH_ARGS)
