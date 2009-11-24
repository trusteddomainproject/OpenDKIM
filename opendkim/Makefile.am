# $Id: Makefile.am,v 1.51 2009/11/24 20:32:29 cm-msk Exp $

if DEBUG
AM_CFLAGS = -g
endif

sbin_PROGRAMS = opendkim-testkey opendkim-testadsp
dist_sbin_SCRIPTS = opendkim-genkey.sh

exampledir = $(docdir)
dist_example_DATA = opendkim.conf.sample

if BUILD_FILTER
sbin_PROGRAMS += opendkim
opendkim_SOURCES = opendkim.c opendkim.h opendkim-ar.c opendkim-ar.h opendkim-arf.c opendkim-arf.h opendkim-config.h opendkim-crypto.c opendkim-crypto.h opendkim-db.c opendkim-db.h config.c config.h stats.c stats.h test.c test.h util.c util.h
opendkim_CC = $(PTHREAD_CC)
opendkim_CFLAGS = $(PTHREAD_CFLAGS)
opendkim_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_LDFLAGS = $(LIBCRYPTO_LIBDIRS) $(LIBMILTER_LIBDIRS) $(PTHREAD_CFLAGS)
opendkim_LDADD = ../libopendkim/libopendkim.la -lmilter $(LIBCRYPTO_LIBS) $(PTHREAD_LIBS)
if USE_DB_OPENDKIM
opendkim_CPPFLAGS += $(LIBDB_INCDIRS)
opendkim_LDFLAGS += $(LIBDB_LIBDIRS)
opendkim_LDADD += $(LIBDB_LIBS)
endif
if USE_ODBX
opendkim_CPPFLAGS += $(LIBODBX_CPPFLAGS)
opendkim_LDADD += $(LIBODBX_LIBS)
endif
if VBR
opendkim_CPPFLAGS += -I$(srcdir)/../libvbr
opendkim_LDADD += ../libvbr/libvbr.la
endif

opendkim_CPPFLAGS += $(LIBMILTER_INCDIRS)
endif

if STATS
sbin_PROGRAMS += opendkim-stats
opendkim_stats_SOURCES = opendkim-db.c opendkim-stats.c util.c
opendkim_stats_CC = $(PTHREAD_CC)
opendkim_stats_CFLAGS = $(PTHREAD_CFLAGS)
opendkim_stats_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBDB_INCDIRS)
opendkim_stats_LDFLAGS = $(LIBDB_LIBDIRS) $(PTHREAD_CFLAGS)
opendkim_stats_LDADD = ../libopendkim/libopendkim.la $(LIBDB_LIBS) $(PTHREAD_LIBS)
endif

opendkim_testkey_SOURCES = opendkim-testkey.c $(srcdir)/../libopendkim/dkim.h $(srcdir)/../libopendkim/dkim-strl.h $(srcdir)/../libopendkim/dkim-test.h
opendkim_testkey_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_testkey_LDFLAGS = $(LIBCRYPTO_LIBDIRS)
opendkim_testkey_LDADD = ../libopendkim/libopendkim.la $(LIBCRYPTO_LIBS) $(LIBRESOLV)

opendkim_testadsp_SOURCES = opendkim-testadsp.c
opendkim_testadsp_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_testadsp_LDADD = ../libopendkim/libopendkim.la $(LIBRESOLV)

man_MANS = opendkim-genkey.8 opendkim-testadsp.8 opendkim-testkey.8
if BUILD_FILTER
man_MANS += opendkim.conf.5 opendkim.8
endif
if STATS
man_MANS += opendkim-stats.8
endif
