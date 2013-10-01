# Copyright (c) 2010-2013, The Trusted Domain Project.  All rights reserved.

AUTOMAKE_OPTIONS = foreign

dist_doc_DATA = README repute.php repute-config.php mkdb-rep.mysql

lib_LTLIBRARIES = librepute.la
librepute_la_SOURCES = repute.c repute.h
librepute_la_LIBADD = $(PTHREAD_LIBS) $(LIBRESOLV) $(CURL_LIBS) $(LIBJANSSON_LIBS) ../libut/libut.la
librepute_la_LDFLAGS = -no-undefined $(PTHREAD_CFLAGS) $(CURL_LDFLAGS) $(LIBJANSSON_LDFLAGS) -version-info 1:0:0
librepute_la_CFLAGS = $(PTHREAD_CFLAGS) $(CURL_CPPFLAGS) $(LIBJANSSON_CPPFLAGS) -I../libut
librepute_la_CC = $(PTHREAD_CC)
libreputeincludedir = $(includedir)/repute
libreputeinclude_HEADERS = repute.h

dist_sbin_SCRIPTS = opendkim-genrates opendkim-modtotals opendkim-rephistory

if RPATH
librepute_la_LDFLAGS += -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = repute.pc

dist_man_MANS = opendkim-genrates.8 opendkim-modtotals.8 opendkim-rephistory.8
#dist_man_MANS = repute.3
