# $Id: Makefile.am,v 1.4 2010/10/25 04:59:44 cm-msk Exp $

lib_LTLIBRARIES = libvbr.la
libvbr_la_SOURCES = vbr.c
libvbr_la_LDFLAGS = -version-info 1:1:0
libvbrincludedir = $(includedir)/vbr
libvbrinclude_HEADERS = vbr.h

if RPATH
libvbr_la_LDFLAGS = -rpath $(libdir)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = vbr.pc
