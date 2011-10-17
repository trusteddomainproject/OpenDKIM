# Copyright (c) 2011, The OpenDKIM Project.  All rights reserved.
#
# $Id: Makefile.am,v 1.6 2010/10/25 17:18:33 cm-msk Exp $

lib_LTLIBRARIES = libut.la
libut_la_SOURCES = ut.c
libut_la_LDFLAGS = -version-info 1:0:0
libutincludedir = $(includedir)/ut
libutinclude_HEADERS = ut.h

if RPATH
libut_la_LDFLAGS += -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ut.pc

dist_man_MANS = ut.3
