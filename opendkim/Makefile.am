# $Id: Makefile.am,v 1.61 2010/02/20 05:34:03 mmarkley Exp $

if DEBUG
AM_CFLAGS = -g
endif

sbin_PROGRAMS = opendkim-genzone opendkim-testkey opendkim-testadsp
dist_sbin_SCRIPTS = opendkim-genkey.sh

exampledir = $(docdir)
dist_example_DATA = opendkim.conf.sample

if BUILD_FILTER
sbin_PROGRAMS += opendkim
opendkim_SOURCES = opendkim.c opendkim.h opendkim-ar.c opendkim-ar.h opendkim-arf.c opendkim-arf.h opendkim-config.h opendkim-crypto.c opendkim-crypto.h opendkim-db.c opendkim-db.h opendkim-lua.c opendkim-lua.h config.c config.h stats.c stats.h test.c test.h util.c util.h
opendkim_CC = $(PTHREAD_CC)
opendkim_CFLAGS = $(PTHREAD_CFLAGS) $(LIBCRYPTO_CFLAGS) $(COV_CFLAGS)
opendkim_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_LDFLAGS = $(LIBCRYPTO_LIBDIRS) $(LIBMILTER_LIBDIRS) $(PTHREAD_CFLAGS) $(COV_LDFLAGS)
opendkim_LDADD = ../libopendkim/libopendkim.la -lmilter $(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) $(COV_LIBADD)
if USE_DB_OPENDKIM
opendkim_CPPFLAGS += $(LIBDB_INCDIRS)
opendkim_LDFLAGS += $(LIBDB_LIBDIRS)
opendkim_LDADD += $(LIBDB_LIBS)
endif
if USE_ODBX
opendkim_CPPFLAGS += $(LIBODBX_CPPFLAGS)
opendkim_LDADD += $(LIBODBX_LIBS)
endif
if LUA
opendkim_CPPFLAGS += $(LIBLUA_INCDIRS)
opendkim_LDFLAGS += $(LIBLUA_LIBDIRS)
opendkim_LDADD += $(LIBLUA_LIBS)
endif
if USE_SASL
opendkim_CPPFLAGS += $(SASL_CPPFLAGS)
endif
if USE_LDAP
opendkim_CPPFLAGS += $(OPENLDAP_CPPFLAGS)
opendkim_LDADD += $(OPENLDAP_LIBS)
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
opendkim_stats_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBDB_INCDIRS)
opendkim_stats_LDFLAGS = $(LIBDB_LIBDIRS) $(PTHREAD_CFLAGS) $(COV_LDFLAGS)
opendkim_stats_LDADD = ../libopendkim/libopendkim.la $(LIBDB_LIBS) $(COV_LIBADD) $(LIBCRYPTO_LIBS)
opendkim_stats_CFLAGS = $(COV_CFLAGS)
if LUA
opendkim_stats_CPPFLAGS += $(LIBLUA_INCDIRS)
opendkim_stats_LDFLAGS += $(LIBLUA_LIBDIRS)
opendkim_stats_LDADD += $(LIBLUA_LIBS)
endif
if USE_ARLIB
opendkim_stats_CC = $(PTHREAD_CC)
opendkim_stats_CFLAGS += $(PTHREAD_CFLAGS)
opendkim_stats_LDADD += $(PTHREAD_LIBS)
endif
endif

opendkim_testkey_SOURCES = opendkim-testkey.c $(srcdir)/../libopendkim/dkim.h $(srcdir)/../libopendkim/dkim-strl.h $(srcdir)/../libopendkim/dkim-test.h
opendkim_testkey_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_testkey_CFLAGS = $(LIBCRYPTO_CFLAGS) $(COV_CFLAGS)
opendkim_testkey_LDFLAGS = $(LIBCRYPTO_LIBDIRS) $(COV_LDFLAGS)
opendkim_testkey_LDADD = ../libopendkim/libopendkim.la $(LIBCRYPTO_LIBS) $(LIBRESOLV) $(COV_LIBADD)
if USE_ARLIB
opendkim_testkey_CC = $(PTHREAD_CC)
opendkim_testkey_CFLAGS += $(PTHREAD_CFLAGS)
endif

opendkim_testadsp_SOURCES = opendkim-testadsp.c
opendkim_testadsp_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_testadsp_CFLAGS = $(LIBCRYPTO_CFLAGS) $(COV_CFLAGS)
opendkim_testadsp_LDFLAGS = $(COV_LDFLAGS)
opendkim_testadsp_LDADD = ../libopendkim/libopendkim.la $(LIBCRYPTO_LIBS) $(LIBRESOLV) $(COV_LIBADD)
if USE_ARLIB
opendkim_testadsp_CC = $(PTHREAD_CC)
opendkim_testadsp_CFLAGS += $(PTHREAD_CFLAGS)
opendkim_testadsp_LDADD += $(PTHREAD_LIBS)
endif

opendkim_genzone_SOURCES = opendkim-db.c opendkim-genzone.c util.c
opendkim_genzone_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_genzone_CFLAGS = $(LIBCRYPTO_CFLAGS) $(COV_CFLAGS)
opendkim_genzone_LDFLAGS = $(COV_LDFLAGS)
opendkim_genzone_LDADD = ../libopendkim/libopendkim.la $(LIBCRYPTO_LIBS) $(COV_LIBADD)
if LUA
opendkim_genzone_CPPFLAGS += $(LIBLUA_INCDIRS)
opendkim_genzone_LDFLAGS += $(LIBLUA_LIBDIRS)
opendkim_genzone_LDADD += $(LIBLUA_LIBS)
endif
if USE_DB_OPENDKIM
opendkim_genzone_CPPFLAGS += $(LIBDB_INCDIRS)
opendkim_genzone_LDFLAGS += $(LIBDB_LIBDIRS)
opendkim_genzone_LDADD += $(LIBDB_LIBS)
endif
if USE_ODBX
opendkim_genzone_CPPFLAGS += $(LIBODBX_CPPFLAGS)
opendkim_genzone_LDADD += $(LIBODBX_LIBS)
endif
if USE_SASL
opendkim_genzone_CPPFLAGS += $(SASL_CPPFLAGS)
endif
if USE_LDAP
opendkim_genzone_CPPFLAGS += $(OPENLDAP_CPPFLAGS)
opendkim_genzone_LDADD += $(OPENLDAP_LIBS)
endif

man_MANS = opendkim-genkey.8 opendkim-genzone.8 opendkim-testadsp.8 opendkim-testkey.8
if BUILD_FILTER
man_MANS += opendkim-lua.3 opendkim.conf.5 opendkim.8
endif
if STATS
man_MANS += opendkim-stats.8
endif
