# $Id$

AM_CPPFLAGS = -I$(top_srcdir)/lib $(WFLAGS) $(GSSAPI_CFLAGS)
LDADD = ../lib/libknc.la

bin_PROGRAMS = unit unit-simple testknc servefile
noinst_PROGRAMS = benchio
check_PROGRAMS = unit-stream unit-pollfds unit-eof unit-lz4
TEST_EXTENSIONS = .py
PY_LOG_COMPILER = python3
TESTS_ENVIRONMENT = KNC=$(abs_top_builddir)/bin/knc
TESTS = unit-stream unit-pollfds unit-eof unit-lz4 \
    knc-handshake-timeout.py

benchio_SOURCES = benchio.c
benchio_LDADD =
unit_stream_SOURCES = unit-stream.c ../lib/lz4.c ../lib/lz4frame.c \
    ../lib/lz4hc.c ../lib/xxhash.c
unit_pollfds_SOURCES = unit-pollfds.c ../lib/lz4.c ../lib/lz4frame.c \
    ../lib/lz4hc.c ../lib/xxhash.c
unit_eof_SOURCES = unit-eof.c ../lib/lz4.c ../lib/lz4frame.c \
    ../lib/lz4hc.c ../lib/xxhash.c
unit_lz4_SOURCES = unit-lz4.c ../lib/lz4.c ../lib/lz4frame.c \
    ../lib/lz4hc.c ../lib/xxhash.c

unit_stream_LDADD = $(GSSAPI_LIBS)
unit_pollfds_LDADD = $(GSSAPI_LIBS)
unit_eof_LDADD = $(GSSAPI_LIBS)
unit_lz4_LDADD = $(GSSAPI_LIBS)

EXTRA_DIST = knc-exec-tests.py knc-bench.py knc-handshake-timeout.py \
    knc-throughput-bench.py
KNC_EXEC_TEST_ARGS =
KNC_BENCH_ARGS =
KNC_THROUGHPUT_BENCH_ARGS =

.PHONY: check-knc-exec
check-knc-exec:
	python3 $(srcdir)/knc-exec-tests.py --knc $(top_builddir)/bin/knc $(KNC_EXEC_TEST_ARGS)

.PHONY: bench-knc
bench-knc:
	LD_LIBRARY_PATH=$(top_builddir)/lib/.libs$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}} \
	    python3 $(srcdir)/knc-bench.py --old-knc /usr/local/bin/knc --new-knc $(top_builddir)/bin/.libs/knc $(KNC_BENCH_ARGS)

.PHONY: bench-knc-throughput
bench-knc-throughput: benchio
	python3 -u $(srcdir)/knc-throughput-bench.py --new-knc $(top_builddir)/bin/.libs/knc --libdir $(top_builddir)/lib/.libs --benchio $(builddir)/benchio $(KNC_THROUGHPUT_BENCH_ARGS)
