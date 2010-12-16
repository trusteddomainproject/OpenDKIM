# Copyright (c) 2010, The OpenDKIM Project.  All rights reserved.
#
# $Id: Makefile.am,v 1.6 2010/10/25 17:18:33 cm-msk Exp $

lib_LTLIBRARIES = libvbr.la
libvbr_la_SOURCES = vbr.c
libvbr_la_LDFLAGS = -version-info 2:0:0
libvbrincludedir = $(includedir)/vbr
libvbrinclude_HEADERS = vbr.h

if RPATH
libvbr_la_LDFLAGS += -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = vbr.pc

dist_man_MANS = vbr.3
