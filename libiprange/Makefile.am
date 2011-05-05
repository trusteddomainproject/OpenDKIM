# Copyright (c) 2011, The OpenDKIM Project.  All rights reserved.
#
# $Id: Makefile.am,v 1.6 2010/10/25 17:18:33 cm-msk Exp $

lib_LTLIBRARIES = libiprange.la
libiprange_la_SOURCES = iprange.c
libiprange_la_LDFLAGS = -version-info 1:0:0
libiprangeincludedir = $(includedir)/iprange
libiprangeinclude_HEADERS = iprange.h

if RPATH
libiprange_la_LDFLAGS += -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = iprange.pc

dist_man_MANS = iprange.3
