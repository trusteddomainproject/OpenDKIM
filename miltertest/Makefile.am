# $Id: Makefile.am,v 1.8 2010/09/05 11:46:25 grooverdan Exp $

# what flags you want to pass to the C compiler & linker
AM_CFLAGS = --pedantic -Wall -O2

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile
if LUA
sbin_PROGRAMS = miltertest

miltertest_SOURCES = miltertest.c
miltertest_CC = $(PTHREAD_CC)
miltertest_CFLAGS = $(PTHREAD_CFLAGS)
miltertest_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBMILTER_INCDIRS) $(LIBLUA_INCDIRS)
miltertest_LDFLAGS = ../libopendkim/libopendkim.la $(LIBLUA_LIBDIRS) $(PTHREAD_CFLAGS)
miltertest_LDADD = $(LIBLUA_LIBS) $(PTHREAD_LIBS)

man_MANS = miltertest.8
endif

EXTRA_DIST = miltertest.8
