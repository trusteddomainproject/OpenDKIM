# Copyright (c) 2010, The OpenDKIM Project.  All rights reserved.
#
# $Id: Makefile.am,v 1.10.2.1 2010/10/28 04:32:07 cm-msk Exp $

# what flags you want to pass to the C compiler & linker
#AM_CFLAGS = --pedantic -Wall -O2

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile
if LUA
sbin_PROGRAMS = miltertest

miltertest_SOURCES = miltertest.c
miltertest_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBMILTER_INCDIRS) $(LIBLUA_INCDIRS)
miltertest_LDFLAGS = ../libopendkim/libopendkim.la $(LIBLUA_LIBDIRS)
miltertest_LDADD = $(LIBLUA_LIBS)

man_MANS = miltertest.8
endif

EXTRA_DIST = miltertest.8
