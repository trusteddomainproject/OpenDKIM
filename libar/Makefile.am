# $Id: Makefile.am,v 1.9.16.1 2010/08/09 04:10:03 cm-msk Exp $

SUBDIRS = tests

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
