# Copyright (c) 2010, 2012, 2013, The Trusted Domain Project.
#   All rights reserved.

# what flags you want to pass to the C compiler & linker
#AM_CFLAGS = --pedantic -Wall -O2

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile
if LUA
bin_PROGRAMS = miltertest

miltertest_SOURCES = miltertest.c
miltertest_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBMILTER_INCDIRS) $(LIBLUA_INCDIRS)
miltertest_LDFLAGS = ../libopendkim/libopendkim.la $(LIBLUA_LIBDIRS)
miltertest_LDADD = $(LIBLUA_LIBS) $(LIBNSL_LIBS)

man_MANS = miltertest.8
endif

EXTRA_DIST = miltertest.8
