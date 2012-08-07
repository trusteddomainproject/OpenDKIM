# Copyright (c) 2010-2012, The OpenDKIM Project.  All rights reserved.
#

if LIVE_TESTS
SUBDIRS = tests
endif

lib_LTLIBRARIES = libar.la
libar_la_SOURCES = ar.c ar-socket.c ar-strl.c manual.c ar-socket.h ar-strl.h manual.h
libar_la_LIBADD = $(PTHREAD_LIBS) $(LIBRESOLV)
libar_la_LDFLAGS = -no-undefined $(PTHREAD_CFLAGS) -version-info 3:0:0
libar_la_CFLAGS = $(PTHREAD_CFLAGS)
libar_la_CC = $(PTHREAD_CC)
libarincludedir = $(includedir)
libarinclude_HEADERS = async-resolv.h

if RPATH
libar_la_LDFLAGS += -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ar.pc

dist_man_MANS = ar.3
