# $Id: Makefile.am,v 1.11 2010/09/23 05:53:48 cm-msk Exp $

SUBDIRS = tests

lib_LTLIBRARIES = libar.la
libar_la_SOURCES = ar.c ar-strl.c manual.c ar-strl.h
libar_la_LIBADD = $(PTHREAD_LIBS) $(LIBRESOLV)
libar_la_LDFLAGS = -no-undefined $(PTHREAD_CFLAGS) -version-info 2:0:0
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
