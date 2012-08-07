# Copyright (c) 2010, 2012, The Trusted Domain Project.  All rights reserved.
#

lib_LTLIBRARIES = libvbr.la
libvbr_la_SOURCES = vbr.c
libvbr_la_LDFLAGS = -version-info 2:0:0 $(LIBRESOLV)
libvbrincludedir = $(includedir)/vbr
libvbrinclude_HEADERS = vbr.h

if RPATH
libvbr_la_LDFLAGS += -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = vbr.pc

dist_man_MANS = vbr.3
