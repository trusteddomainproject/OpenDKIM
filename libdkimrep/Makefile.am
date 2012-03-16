# Copyright (c) 2011, 2012, The OpenDKIM Project.  All rights reserved.
#
# $Id: Makefile.am,v 1.6 2010/10/25 17:18:33 cm-msk Exp $

if LIVE_TESTS
SUBDIRS = tests
endif

lib_LTLIBRARIES = libdkimrep.la
libdkimrep_la_SOURCES = dkim-rep.c dkim-rep.h
libdkimrep_la_LDFLAGS = -no-undefined -version-info 1:0:0 $(LIBCRYPTO_LIBDIRS) $(COV_LDFLAGS) $(LIBRESOLV)
libdkimrep_la_CFLAGS = $(LIBCRYPTO_CFLAGS) $(COV_CFLAGS)
libdkimrep_la_CPPFLAGS = $(LIBCRYPTO_CPPFLAGS)
libdkimrep_la_LIBADD = $(LIBCRYPTO_LIBS) $(COV_LIBADD)

libdkimrepinclude_HEADERS = dkim-rep.h
libdkimrepincludedir = $(includedir)/dkim-rep

if RPATH
libdkimrep_la_LDFLAGS += -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = dkim-rep.pc

dist_man_MANS = dkim-rep.3
