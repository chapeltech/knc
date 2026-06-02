# $Id$

AM_CPPFLAGS = $(GSSAPI_CFLAGS) -DKNC_VERSION_STRING=\"1.12\"

bin_PROGRAMS = knc

knc_SOURCES = knc.c
knc_CPPFLAGS = $(AM_CPPFLAGS) -DUSE_LIBKNC -I$(top_srcdir)/lib
knc_LDADD = ../lib/libknc.la $(GSSAPI_LIBS)

man_MANS = knc.1
