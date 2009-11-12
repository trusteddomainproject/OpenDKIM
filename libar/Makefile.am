# $Id: Makefile.am,v 1.7.8.1 2009/11/12 01:52:06 grooverdan Exp $

lib_LTLIBRARIES = libar.la
libar_la_SOURCES = ar.c ar-strl.c manual.c ar-strl.h
libarincludedir = $(includedir)/ar
libarinclude_HEADERS = ar.h manual.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ar.pc

man_MANS = ar.3
EXTRA_DIST = $(man_MANS)
