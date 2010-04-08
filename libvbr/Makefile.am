# $Id: Makefile.am,v 1.2.8.2 2010/04/08 00:05:13 cm-msk Exp $

lib_LTLIBRARIES = libvbr.la
libvbr_la_SOURCES = vbr.c
libvbrincludedir = $(includedir)/vbr
libvbrinclude_HEADERS = vbr.h

if RPATH
libvbr_la_LDFLAGS = -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = vbr.pc
