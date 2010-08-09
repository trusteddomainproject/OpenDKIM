# $Id: Makefile.am,v 1.1.2.2 2010/08/09 04:09:39 cm-msk Exp $

AM_CFLAGS = $(COV_CFLAGS) $(PTHREAD_CFLAGS)
AM_LDFLAGS = $(COV_LDFLAGS) $(PTHREAD_LDFLAGS)

if DEBUG
AM_CFLAGS += -g
endif

LDADD = ../libar.la $(COV_LIBADD) $(PTHREAD_LDADD)
AM_CPPFLAGS = -I..

check_PROGRAMS = ar_test00 ar_test01

TESTS = $(check_PROGRAMS)

ar_test00_SOURCES = ar-test00.c
ar_test01_SOURCES = ar-test01.c

MOSTLYCLEANFILES=
