# $Id: Makefile.am,v 1.3 2010/09/06 22:35:17 grooverdan Exp $

AM_CFLAGS = $(COV_CFLAGS)
AM_LDFLAGS = $(COV_LDFLAGS)

if DEBUG
AM_CFLAGS += -g
endif

LDADD = ../libar.la $(COV_LIBADD) $(LIBRESOLV)
AM_CPPFLAGS = -I..

check_PROGRAMS = ar_test00 ar_test01

TESTS = $(check_PROGRAMS)

ar_test00_SOURCES = ar-test00.c
ar_test01_SOURCES = ar-test01.c

MOSTLYCLEANFILES=
