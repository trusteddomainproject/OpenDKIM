# Copyright (c) 2010, 2011, The OpenDKIM Project.  All rights reserved.
#
# $Id: Makefile.am,v 1.7 2010/10/25 17:13:17 cm-msk Exp $

if USE_ODBX

bin_PROGRAMS = opendkim-anonstats opendkim-importstats

opendkim_anonstats_SOURCES = opendkim-anonstats.c
opendkim_anonstats_CPPFLAGS = $(LIBCRYPTO_CPPFLAGS)
opendkim_anonstats_CFLAGS = $(LIBCRYPTO_CFLAGS)
opendkim_anonstats_LDFLAGS = $(LIBCRYPTO_LIBDIRS)
opendkim_anonstats_LDADD = $(LIBCRYPTO_LIBS)

opendkim_importstats_SOURCES = opendkim-importstats.c
opendkim_importstats_CPPFLAGS = $(LIBODBX_CPPFLAGS) -I$(srcdir)/../libopendkim
opendkim_importstats_CFLAGS = $(LIBODBX_CFLAGS) $(COV_CFLAGS)
opendkim_importstats_LDFLAGS = $(COV_LDFLAGS)
opendkim_importstats_LDADD = $(LIBODBX_LIBS) ../libopendkim/libopendkim.la $(COV_LIBADD)

exampledir = @docdir@
dist_example_DATA = mkdb.mysql

dist_doc_DATA = README
dist_bin_SCRIPTS = opendkim-gengraphs opendkim-genstats

man_MANS = opendkim-anonstats.8 opendkim-importstats.8

endif
