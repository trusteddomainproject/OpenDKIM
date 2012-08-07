# Copyright (c) 2011, 2012, The Trusted Domain Project.  All rights reserved.
#

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
