# $Id: Makefile.am,v 1.3 2010/09/06 22:35:17 grooverdan Exp $

AM_CFLAGS = $(COV_CFLAGS)
AM_LDFLAGS = $(COV_LDFLAGS)

if DEBUG
AM_CFLAGS += -g
endif

LDADD = ../libdkimrep.la $(COV_LIBADD) $(LIBRESOLV)
AM_CPPFLAGS = -I..

check_PROGRAMS = dr_test00

TESTS = $(check_PROGRAMS)

dr_test00_SOURCES = dr-test00.c

MOSTLYCLEANFILES=
