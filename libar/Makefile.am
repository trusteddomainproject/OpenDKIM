# $Id: Makefile.am,v 1.8.8.2 2010/04/08 00:05:13 cm-msk Exp $

lib_LTLIBRARIES = libar.la
libar_la_SOURCES = ar.c ar-strl.c manual.c ar-strl.h
libar_la_LIBADD = $(PTHREAD_LIBS)
libar_la_LDFLAGS = $(PTHREAD_CFLAGS)
libar_la_CFLAGS = $(PTHREAD_CFLAGS)
libar_la_CC = $(PTHREAD_CC)
libarincludedir = $(includedir)/ar
libarinclude_HEADERS = ar.h manual.h

if RPATH
libar_la_LDFLAGS += -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ar.pc

dist_man_MANS = ar.3
