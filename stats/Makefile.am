# Copyright (c) 2010-2012, The OpenDKIM Project.  All rights reserved.
#

if USE_ODBX

bin_PROGRAMS = opendkim-importstats

opendkim_importstats_SOURCES = opendkim-importstats.c
opendkim_importstats_CPPFLAGS = $(LIBODBX_CPPFLAGS) -I$(srcdir)/../libopendkim -I$(srcdir)/../opendkim
opendkim_importstats_CFLAGS = $(LIBODBX_CFLAGS) $(COV_CFLAGS)
opendkim_importstats_LDFLAGS = $(COV_LDFLAGS)
opendkim_importstats_LDADD = $(LIBODBX_LIBS) ../libopendkim/libopendkim.la $(COV_LIBADD)

exampledir = @docdir@
dist_example_DATA = mkdb.mysql

dist_doc_DATA = README
dist_bin_SCRIPTS = opendkim-expire opendkim-gengraphs opendkim-genstats \
	opendkim-reportstats

man_MANS = opendkim-expire.8 opendkim-gengraphs.8 opendkim-genstats.8 \
	opendkim-importstats.8

endif
