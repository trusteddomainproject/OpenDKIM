# $Id: Makefile.am,v 1.8 2009/11/22 08:15:50 grooverdan Exp $

lib_LTLIBRARIES = libar.la
libar_la_SOURCES = ar.c ar-strl.c manual.c ar-strl.h
libar_la_LIBADD = $(PTHREAD_LIBS)
libar_la_LDFLAGS = $(PTHREAD_CFLAGS)
libar_la_CFLAGS = $(PTHREAD_CFLAGS)
libar_la_CC = $(PTHREAD_CC)
libarincludedir = $(includedir)/ar
libarinclude_HEADERS = ar.h manual.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ar.pc

dist_man_MANS = ar.3
