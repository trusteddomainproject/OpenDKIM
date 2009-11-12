# $Id: Makefile.am,v 1.48.4.2 2009/11/12 06:56:25 grooverdan Exp $

# what flags you want to pass to the C compiler & linker
AM_CFLAGS = -pthread --pedantic -Wall -O2
AM_LDFLAGS = -pthread

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile
sbin_PROGRAMS = opendkim-testkey opendkim-testadsp
sbin_SCRIPTS = opendkim-genkey.sh

exampledir = $(docdir)
example_DATA = opendkim.conf.sample

if BUILD_FILTER
sbin_PROGRAMS += opendkim
opendkim_SOURCES = opendkim.c opendkim.h opendkim-ar.c opendkim-ar.h opendkim-arf.c opendkim-arf.h opendkim-config.h opendkim-crypto.c opendkim-crypto.h opendkim-db.c opendkim-db.h config.c config.h stats.c stats.h test.c test.h util.c util.h
opendkim_CFLAGS = 
opendkim_CPPFLAGS = -I../libopendkim $(LIBCRYPTO_CFLAGS)
opendkim_LDFLAGS = -L../libopendkim $(LIBCRYPTO_LIBDIRS) $(LIBMILTER_LIBDIRS)
opendkim_LDADD = ../libopendkim/libopendkim.la -lmilter $(LIBCRYPTO_LIBS)
if DEBUG
opendkim_CFLAGS += -g
endif
if USE_DB_OPENDKIM
opendkim_CPPFLAGS += $(LIBDB_INCDIRS)
opendkim_LDFLAGS += $(LIBDB_LIBDIRS)
opendkim_LDADD += $(LIBDB_LIBS)
endif
if USE_ODBX
opendkim_CPPFLAGS += $(LIBODBX_INCDIRS)
opendkim_LDFLAGS += $(LIBODBX_LIBDIRS)
opendkim_LDADD += $(LIBODBX_LIBS)
endif
if VBR
opendkim_CPPFLAGS += -I../libvbr
opendkim_LDFLAGS += -L../libvbr
opendkim_LDADD += ../libvbr/libvbr.la
endif

opendkim_CPPFLAGS += $(LIBMILTER_INCDIRS)
endif

if STATS
sbin_PROGRAMS += opendkim-stats
opendkim_stats_SOURCES = opendkim-db.c opendkim-stats.c util.c
opendkim_stats_CPPFLAGS = -I../libopendkim $(LIBDB_INCDIRS)
opendkim_stats_LDFLAGS = -L../libopendkim $(LIBDB_LIBDIRS)
opendkim_stats_LDADD = ../libopendkim/libopendkim.la $(LIBDB_LIBS)
if DEBUG
opendkim_stats_CFLAGS = -g
endif
endif

opendkim_testkey_SOURCES = opendkim-testkey.c
opendkim_testkey_CPPFLAGS = -I../libopendkim $(LIBCRYPTO_CFLAGS)
opendkim_testkey_LDFLAGS = -L../libopendkim $(LIBCRYPTO_LIBDIRS)
opendkim_testkey_LDADD = ../libopendkim/libopendkim.la $(LIBCRYPTO_LIBS) @LIBRESOLV@
opendkim_testkey_CFLAGS = 
if DEBUG
opendkim_testkey_CFLAGS += -g
endif

opendkim_testadsp_SOURCES = opendkim-testadsp.c
opendkim_testadsp_CPPFLAGS = -I../libopendkim $(LIBCRYPTO_CFLAGS)
opendkim_testadsp_LDFLAGS = -L../libopendkim
opendkim_testadsp_LDADD = ../libopendkim/libopendkim.la @LIBRESOLV@
opendkim_testadsp_CFLAGS = 
if DEBUG
opendkim_testadsp_CFLAGS += -g
endif

man_MANS = opendkim-genkey.8 opendkim-testadsp.8 opendkim-testkey.8
if BUILD_FILTER
man_MANS += opendkim.conf.5 opendkim.8
endif
if STATS
man_MANS += opendkim-stats.8
endif

EXTRA_DIST = $(example_DATA) $(man_MANS) opendkim-stats.8 $(sbin_SCRIPTS)
