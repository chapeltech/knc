# $Id$

AM_CPPFLAGS = -I$(top_srcdir)/lib $(WFLAGS) $(GSSAPI_CFLAGS)
LDADD = ../lib/libknc.la

bin_PROGRAMS = unit unit-simple testknc servefile
check_PROGRAMS = unit-pollfds
TESTS = unit-pollfds

check_PROGRAMS = unit-stream
TESTS = unit-stream

unit_stream_SOURCES = unit-stream.c
unit_stream_LDADD = $(GSSAPI_LIBS)

EXTRA_DIST = knc-exec-tests.py
KNC_EXEC_TEST_ARGS =

.PHONY: check-knc-exec
check-knc-exec:
	python3 $(srcdir)/knc-exec-tests.py --knc $(top_builddir)/bin/knc $(KNC_EXEC_TEST_ARGS)
