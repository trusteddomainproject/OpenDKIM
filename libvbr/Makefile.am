# $Id: Makefile.am,v 1.3 2010/04/12 15:08:46 cm-msk Exp $

lib_LTLIBRARIES = libvbr.la
libvbr_la_SOURCES = vbr.c
libvbrincludedir = $(includedir)/vbr
libvbrinclude_HEADERS = vbr.h

if RPATH
libvbr_la_LDFLAGS = -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = vbr.pc
