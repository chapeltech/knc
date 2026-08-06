# $Id$

AM_CPPFLAGS = $(GSSAPI_CFLAGS) -DKNC_VERSION_STRING=\"1.13\"

bin_PROGRAMS = knc

knc_SOURCES = knc.c gssstdio.c
knc_LDADD = $(GSSAPI_LIBS)

man_MANS = knc.1
