#

lib_LTLIBRARIES	= libknc.la
man_MANS	= libknc.3
include_HEADERS	= libknc.h

libknc_la_SOURCES = libknc.c simple.c lz4.c lz4frame.c lz4hc.c xxhash.c
libknc_la_LIBADD  = $(GSSAPI_LIBS)
libknc_la_CFLAGS  = $(HARDEN_CFLAGS)
libknc_la_LDFLAGS = $(HARDEN_LDFLAGS) -export-symbols-regex '^knc_'

#
# Let's be a tad more aggressive about warnings:

libknc_la_CPPFLAGS  = $(WFLAGS) $(HARDEN_CPPFLAGS) $(GSSAPI_CFLAGS)
