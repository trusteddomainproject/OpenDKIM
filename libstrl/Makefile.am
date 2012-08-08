# Copyright (c) 2011, 2012, The Trusted Domain Project.  All rights reserved.
#

lib_LTLIBRARIES = libstrl.la
libstrl_la_SOURCES = strl.c
libstrl_la_LDFLAGS = -version-info 1:0:0
libstrlincludedir = $(includedir)/strl
libstrlinclude_HEADERS = strl.h

if RPATH
libstrl_la_LDFLAGS += -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = strl.pc

dist_man_MANS = strl.3
