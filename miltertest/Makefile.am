# $Id: Makefile.am,v 1.2 2010/01/14 05:58:50 cm-msk Exp $

# what flags you want to pass to the C compiler & linker
AM_CFLAGS = -pthread --pedantic -Wall -O2
AM_LDFLAGS = -pthread

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile
if LUA
sbin_PROGRAMS = miltertest

miltertest_SOURCES = miltertest.c
miltertest_CFLAGS = 
miltertest_CPPFLAGS = $(LIBMILTER_INCDIRS) $(LIBLUA_INCDIRS)
miltertest_LDFLAGS = $(LIBLUA_LIBDIRS)
miltertest_LDADD = $(LIBLUA_LIBS)

man_MANS = miltertest.8

EXTRA_DIST = $(man_MANS)
endif
