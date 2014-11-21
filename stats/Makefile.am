# Copyright (c) 2010-2014, The Trusted Domain Project.  All rights reserved.

exampledir = @docdir@
dist_example_DATA = mkdb.mysql

dist_doc_DATA = README README.opendkim-reportstats
dist_sbin_SCRIPTS = opendkim-expire opendkim-gengraphs opendkim-genstats \
	opendkim-reportstats

man_MANS = opendkim-expire.8 opendkim-gengraphs.8 opendkim-genstats.8

if USE_ODBX

sbin_PROGRAMS = opendkim-importstats

opendkim_importstats_SOURCES = opendkim-importstats.c
opendkim_importstats_CPPFLAGS = $(LIBODBX_CPPFLAGS) -I$(srcdir)/../libopendkim -I$(srcdir)/../opendkim
opendkim_importstats_CFLAGS = $(LIBODBX_CFLAGS) $(COV_CFLAGS)
opendkim_importstats_LDFLAGS = $(LIBODBX_LDFLAGS) $(COV_LDFLAGS)
opendkim_importstats_LDADD = $(LIBODBX_LIBS) $(LIBDL_LIBS) $(COV_LIBADD)

man_MANS += opendkim-importstats.8

endif
