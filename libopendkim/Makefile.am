# Copyright (c) 2010-2014, The Trusted Domain Project.  All rights reserved.

SUBDIRS=tests docs

if DEBUG
AM_CFLAGS = -g
endif
LDADD = ./libopendkim.la

lib_LTLIBRARIES = libopendkim.la
libopendkim_la_SOURCES = base32.c base64.c dkim-atps.c dkim-cache.c dkim-canon.c dkim-dns.c dkim-keys.c dkim-mailparse.c dkim-report.c dkim-tables.c dkim-test.c dkim-util.c dkim.c util.c base64.h dkim-cache.h dkim-canon.h dkim-dns.h dkim-internal.h dkim-keys.h dkim-mailparse.h dkim-report.h dkim-tables.h dkim-test.h dkim-types.h dkim-util.h dkim.h util.h
libopendkim_la_CPPFLAGS = $(LIBCRYPTO_CPPFLAGS)
libopendkim_la_CFLAGS = $(LIBCRYPTO_INCDIRS) $(LIBOPENDKIM_INC) $(COV_CFLAGS)
libopendkim_la_LDFLAGS = -no-undefined  $(LIBCRYPTO_LIBDIRS) $(COV_LDFLAGS) -version-info $(LIBOPENDKIM_VERSION_INFO)
libopendkim_la_LIBADD = $(LIBOPENDKIM_LIBS) $(LIBCRYPTO_LDADD) $(COV_LIBADD)
if !ALL_SYMBOLS
libopendkim_la_DEPENDENCIES = symbols.map
libopendkim_la_LDFLAGS += -export-symbols symbols.map
endif
if RPATH
libopendkim_la_LDFLAGS += -rpath $(libdir)
endif
libopendkim_includedir = $(includedir)/opendkim
libopendkim_include_HEADERS = dkim.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = opendkim.pc

if USE_DB_LIBOPENDKIM
libopendkim_la_CPPFLAGS += -I$(LIBDB_INCDIRS)
libopendkim_la_LDFLAGS += $(LIBDB_LIBDIRS)
libopendkim_la_LIBADD += $(LIBDB_LIBS)
endif

if USE_TRE
libopendkim_la_CFLAGS += $(LIBTRE_CPPFLAGS)
libopendkim_la_LIBADD += $(LIBTRE_LIBS)
endif

DISTCLEANFILES=symbols.map *.gcno *.gcda

symbols.map: $(libopendkim_include_HEADERS)
	grep '^extern' $? | \
		awk '{ for (c = 1; c <= NF; c++) if ($$c ~ /dkim_/) { print $$c; break; } }' | \
		sed -e s/\[\*\;\]//g -e s/\[\\\[\\\]\]//g | \
		sort -u -o $@

MOSTLYCLEANFILES=symbols.map *.gcno *.gcda
