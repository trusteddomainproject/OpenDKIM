# Copyright (c) 2010, 2012, The Trusted Domain Project.  All rights reserved.
#

lib_LTLIBRARIES = librbl.la
librbl_la_SOURCES = rbl.c
librbl_la_LDFLAGS = -version-info 1:0:0 $(LIBRESOLV)
librblincludedir = $(includedir)/rbl
librblinclude_HEADERS = rbl.h

if RPATH
librbl_la_LDFLAGS += -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = rbl.pc

dist_man_MANS = rbl.3
