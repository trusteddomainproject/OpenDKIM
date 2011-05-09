# Copyright (c) 2011, The OpenDKIM Project.  All rights reserved.
#
# $Id: Makefile.am,v 1.6 2010/10/25 17:18:33 cm-msk Exp $

if LIVE_TESTS
SUBDIRS = tests
endif

lib_LTLIBRARIES = libdkimrep.la
libdkimrep_la_SOURCES = dkim-rep.c dkim-rep.h
libdkimrep_la_LDFLAGS = -version-info 1:0:0
libdkimrepinclude_HEADERS = dkim-rep.h
libdkimrepincludedir = $(includedir)/dkim-rep

if RPATH
libdkimrep_la_LDFLAGS += -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = dkim-rep.pc

dist_man_MANS = dkim-rep.3
