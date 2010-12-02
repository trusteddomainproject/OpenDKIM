# Copyright (c) 2010, The OpenDKIM Project.  All rights reserved.
#
# $Id: Makefile.am,v 1.6 2010/10/25 17:18:33 cm-msk Exp $

lib_LTLIBRARIES = librbl.la
librbl_la_SOURCES = rbl.c
librbl_la_LDFLAGS = -version-info 1:0:0
librblincludedir = $(includedir)/rbl
librblinclude_HEADERS = rbl.h

if RPATH
librbl_la_LDFLAGS += -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = rbl.pc
