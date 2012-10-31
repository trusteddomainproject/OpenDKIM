# Copyright (c) 2010-2012, The Trusted Domain Project.  All rights reserved.

AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libreprrd.la
libreprrd_la_SOURCES = reprrd.c reprrd.h
libreprrd_la_LIBADD = $(RRDTOOL_LIBS)
libreprrd_la_LDFLAGS = -no-undefined $(PTHREAD_LDFLAGS) -version-info 1:0:0
libreprrd_la_CFLAGS = $(PTHREAD_CFLAGS) $(RRDTOOL_CFLAGS)
libreprrd_la_CC = $(PTHREAD_CC)
libreprrdincludedir = $(includedir)/reprrd
libreprrdinclude_HEADERS = reprrd.h
if STRL
libreprrd_la_CFLAGS += -I$(top_srcdir)/libstrl
libreprrd_la_LIBADD += ../libstrl/libstrl.la
endif

dist_doc_DATA = README reprrd.php reprrd-config.php

dist_bin_SCRIPTS = opendkim-reprrdimport

dist_man_MANS = opendkim-reprrdimport.8 
