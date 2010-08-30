# $Id: Makefile.am,v 1.3.10.2 2010/08/30 07:33:40 cm-msk Exp $
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
dist_sbin_SCRIPTS = opendkim-genstats

man_MANS = opendkim-importstats.8

endif
