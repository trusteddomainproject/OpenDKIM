# $Id: Makefile.am,v 1.3.10.1 2010/08/18 17:45:26 cm-msk Exp $
#

if USE_ODBX

sbin_PROGRAMS = opendkim-importstats

opendkim_importstats_SOURCES = opendkim-importstats.c opendkim-importstats.h
opendkim_importstats_CPPFLAGS = $(LIBODBX_CPPFLAGS)
opendkim_importstats_CFLAGS = $(LIBODBX_CFLAGS) $(COV_CFLAGS)
opendkim_importstats_LDFLAGS = $(COV_LDFLAGS)
opendkim_importstats_LDADD = $(LIBODBX_LIBS) $(COV_LIBADD)

exampledir = @docdir@
dist_example_DATA = mkdb.mysql

dist_doc_DATA = README

man_MANS = opendkim-importstats.8

endif
