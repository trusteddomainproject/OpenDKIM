# Copyright (c) 2010, 2012, 2014, The Trusted Domain Project.
#   All rights reserved.

# what flags you want to pass to the C compiler & linker
#AM_CFLAGS = --pedantic -Wall -O2

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile
if JANSSON
bin_PROGRAMS = autobuild

autobuild_SOURCES = autobuild.c
autobuild_CPPFLAGS = $(LIBJANSSON_CPPFLAGS)
autobuild_LDFLAGS = $(LIBJANSSON_LDFLAGS)
autobuild_LDADD = $(LIBJANSSON_LIBS) -lm

man_MANS = autobuild.8
dist_doc_DATA = autobuild.conf.sample
endif

EXTRA_DIST = autobuild.8 autobuild.conf.sample
