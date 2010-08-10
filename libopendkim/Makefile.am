# $Id: Makefile.am,v 1.52 2010/08/10 00:14:15 cm-msk Exp $


SUBDIRS=tests docs

if DEBUG
AM_CFLAGS = -g
endif
LDADD = ./libopendkim.la

lib_LTLIBRARIES = libopendkim.la
libopendkim_la_SOURCES = base64.c dkim-cache.c dkim-canon.c dkim-keys.c dkim-mailparse.c dkim-policy.c dkim-rep.c dkim-strl.c dkim-tables.c dkim-test.c dkim-ub.c dkim-util.c dkim.c util.c base64.h dkim-cache.h dkim-canon.h dkim-internal.h dkim-keys.h dkim-mailparse.h dkim-policy.h dkim-rep.h dkim-strl.h dkim-tables.h dkim-test.h dkim-types.h dkim-ub.h dkim-util.h dkim.h util.h
libopendkim_la_CFLAGS = $(LIBOPENDKIM_INC) $(COV_CFLAGS)
libopendkim_la_LDFLAGS = -no-undefined  $(LIBCRYPTO_LIBDIRS) $(COV_LDFLAGS) -version-info $(LIBOPENDKIM_VERSION_INFO)
libopendkim_la_LIBADD = $(LIBOPENDKIM_LIBS) $(COV_LIBADD)
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

if USE_ARLIB
libopendkim_la_CC = $(PTHREAD_CC)
libopendkim_la_LDFLAGS += $(PTHREAD_CFLAGS)
libopendkim_la_LIBADD += $(PTHREAD_LIBS)
libopendkim_la_CFLAGS += -I$(srcdir)/../libar $(PTHREAD_CFLAGS)
libopendkim_la_LIBADD += ../libar/libar.la
endif

if USE_DB_LIBOPENDKIM
libopendkim_la_CFLAGS += -I$(LIBDB_INCDIRS)
libopendkim_la_LDFLAGS += $(LIBDB_LIBDIRS)
libopendkim_la_LIBADD += $(LIBDB_LIBS)
endif

if USE_TRE
libopendkim_la_CFLAGS += $(LIBTRE_CFLAGS)
libopendkim_la_LIBADD += $(LIBTRE_LIBS)
endif

if USE_UNBOUND
libopendkim_la_CC = $(PTHREAD_CC)
libopendkim_la_CFLAGS += $(LIBUNBOUND_INCDIRS) $(PTHREAD_CFLAGS)
libopendkim_la_LDFLAGS += $(LIBUNBOUND_LIBDIRS) $(PTHREAD_CFLAGS)
libopendkim_la_LIBADD += $(LIBUNBOUND_LIBS) $(PTHREAD_LIBS)
endif

DISTCLEANFILES=symbols.map

symbols.map: $(libopendkim_include_HEADERS)
	grep '^extern' $? | \
		awk '{ for (c = 1; c <= NF; c++) if ($$c ~ /dkim_/) { print $$c; break; } }' | \
		sed -e s/\[\*\;\]//g -e s/\[\\\[\\\]\]//g | \
		sort -u -o $@

MOSTLYCLEANFILES=symbols.map
