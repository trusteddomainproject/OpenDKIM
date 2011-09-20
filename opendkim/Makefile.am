# Copyright (c) 2010, 2011, The OpenDKIM Project.  All rights reserved.
#
# $Id: Makefile.am,v 1.85 2010/10/28 04:12:55 cm-msk Exp $

if DEBUG
AM_CFLAGS = -g
endif

bin_PROGRAMS = opendkim-testkey opendkim-testadsp opendkim-genzone
if ATPS
bin_PROGRAMS += opendkim-atpszone
endif
if STATS
bin_PROGRAMS += opendkim-stats
if USE_ODBX
bin_PROGRAMS += opendkim-spam
endif
endif

dist_bin_SCRIPTS = opendkim-genkey
dist_doc_DATA = opendkim.conf.sample opendkim.conf.simple \
	opendkim.conf.simple-verify README.SQL

if BUILD_FILTER
sbin_PROGRAMS = opendkim
opendkim_SOURCES = opendkim.c opendkim.h opendkim-ar.c opendkim-ar.h opendkim-arf.c opendkim-arf.h opendkim-config.h opendkim-crypto.c opendkim-crypto.h opendkim-db.c opendkim-db.h opendkim-dns.c opendkim-dns.h opendkim-lua.c opendkim-lua.h config.c config.h reputation.c reputation.h stats.c stats.h test.c test.h util.c util.h
opendkim_CC = $(PTHREAD_CC)
opendkim_CFLAGS = $(PTHREAD_CFLAGS) $(LIBCRYPTO_CFLAGS) $(COV_CFLAGS)
opendkim_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_LDFLAGS = $(LIBCRYPTO_LIBDIRS) $(LIBMILTER_LIBDIRS) $(PTHREAD_CFLAGS) $(COV_LDFLAGS)
opendkim_LDADD = ../libopendkim/libopendkim.la $(LIBMILTER_LIBS) $(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) $(COV_LIBADD)
if USE_DB_OPENDKIM
opendkim_CPPFLAGS += $(LIBDB_INCDIRS)
opendkim_LDFLAGS += $(LIBDB_LIBDIRS)
opendkim_LDADD += $(LIBDB_LIBS)
endif
if USE_ODBX
opendkim_CPPFLAGS += $(LIBODBX_CPPFLAGS)
opendkim_CFLAGS += $(LIBODBX_CFLAGS)
opendkim_LDADD += $(LIBODBX_LIBS)
endif
if LUA
SUBDIRS=tests
opendkim_CPPFLAGS += $(LIBLUA_INCDIRS) -DDKIMF_LUA_CONTEXT_HOOKS
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
if USE_ARLIB
opendkim_CFLAGS += -I$(srcdir)/../libar
opendkim_LDADD += ../libar/libar.la
endif
if USE_UNBOUND
opendkim_CPPFLAGS += $(LIBUNBOUND_INCDIRS)
opendkim_LDFLAGS += $(LIBUNBOUND_LIBDIRS)
opendkim_LDADD += $(LIBUNBOUND_LIBS)
endif
if VBR
opendkim_CPPFLAGS += -I$(srcdir)/../libvbr
opendkim_LDADD += ../libvbr/libvbr.la
endif
if RBL
opendkim_CPPFLAGS += -I$(srcdir)/../librbl
opendkim_LDADD += ../librbl/librbl.la
endif
if VERIFY_DOMAINKEYS
opendkim_CPPFLAGS += $(LIBDK_INCDIRS)
opendkim_LDFLAGS += $(LIBDK_LIBDIRS)
opendkim_LDADD += $(LIBDK_LIBS)
endif

opendkim_CPPFLAGS += $(LIBMILTER_INCDIRS)
endif

if STATS
opendkim_stats_SOURCES = opendkim-stats.c
opendkim_stats_CPPFLAGS = -I$(srcdir)/../libopendkim
opendkim_stats_LDFLAGS = $(COV_LDFLAGS)
opendkim_stats_LDADD = ../libopendkim/libopendkim.la $(LIBCRYPTO_LIBS) $(COV_LIBADD)
opendkim_stats_CFLAGS = $(LIBCRYPTO_CFLAGS) $(COV_CFLAGS)
endif

opendkim_testkey_SOURCES = config.c config.h opendkim-crypto.c opendkim-crypto.h opendkim-db.c opendkim-db.h opendkim-dns.c opendkim-dns.h opendkim-lua.c opendkim-lua.h opendkim-testkey.c util.c util.h $(srcdir)/../libopendkim/dkim.h $(srcdir)/../libopendkim/dkim-strl.h $(srcdir)/../libopendkim/dkim-test.h
opendkim_testkey_CC = $(PTHREAD_CC)
opendkim_testkey_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_testkey_CFLAGS = $(LIBCRYPTO_CFLAGS) $(COV_CFLAGS) $(PTHREAD_CFLAGS)
opendkim_testkey_LDFLAGS = $(LIBCRYPTO_LIBDIRS) $(COV_LDFLAGS)
opendkim_testkey_LDADD = ../libopendkim/libopendkim.la $(LIBCRYPTO_LIBS) $(LIBRESOLV) $(COV_LIBADD) $(PTHREAD_LIBS)
if LUA
opendkim_testkey_CPPFLAGS += $(LIBLUA_INCDIRS) $(LIBMILTER_INCDIRS)
opendkim_testkey_LDFLAGS += $(LIBLUA_LIBDIRS)
opendkim_testkey_LDADD += $(LIBLUA_LIBS)
endif
if USE_DB_OPENDKIM
opendkim_testkey_CPPFLAGS += $(LIBDB_INCDIRS)
opendkim_testkey_LDFLAGS += $(LIBDB_LIBDIRS)
opendkim_testkey_LDADD += $(LIBDB_LIBS)
endif
if USE_ODBX
opendkim_testkey_CPPFLAGS += $(LIBODBX_CPPFLAGS)
opendkim_testkey_CFLAGS += $(LIBODBX_CFLAGS)
opendkim_testkey_LDADD += $(LIBODBX_LIBS)
endif
if USE_LDAP
opendkim_testkey_CPPFLAGS += $(OPENLDAP_CPPFLAGS)
opendkim_testkey_LDADD += $(OPENLDAP_LIBS)
endif
if USE_SASL
opendkim_testkey_CPPFLAGS += $(SASL_CPPFLAGS)
endif
if USE_UNBOUND
opendkim_testkey_CPPFLAGS += $(LIBUNBOUND_INCDIRS)
opendkim_testkey_LDFLAGS += $(LIBUNBOUND_LIBDIRS)
opendkim_testkey_LDADD += $(LIBUNBOUND_LIBS)
endif
if USE_ARLIB
opendkim_testkey_CFLAGS += -I$(srcdir)/../libar
opendkim_testkey_LDADD += ../libar/libar.la
endif
if RBL
opendkim_testkey_CPPFLAGS += -I$(srcdir)/../librbl
opendkim_testkey_LDADD += ../librbl/librbl.la
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

opendkim_genzone_SOURCES = config.c config.h opendkim-db.c opendkim-db.h opendkim-genzone.c opendkim-lua.c util.c util.h
opendkim_genzone_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_genzone_CFLAGS = $(LIBCRYPTO_CFLAGS) $(COV_CFLAGS)
opendkim_genzone_LDFLAGS = $(COV_LDFLAGS) $(LIBCRYPTO_LIBDIRS)
opendkim_genzone_LDADD = ../libopendkim/libopendkim.la $(LIBCRYPTO_LIBS) $(COV_LIBADD)
if USE_DB_OPENDKIM
opendkim_genzone_CPPFLAGS += $(LIBDB_INCDIRS)
opendkim_genzone_LDFLAGS += $(LIBDB_LIBDIRS)
opendkim_genzone_LDADD += $(LIBDB_LIBS)
endif
if USE_ODBX
opendkim_genzone_CPPFLAGS += $(LIBODBX_CPPFLAGS)
opendkim_genzone_CFLAGS += $(LIBODBX_CFLAGS)
opendkim_genzone_LDADD += $(LIBODBX_LIBS)
endif
if USE_SASL
opendkim_genzone_CPPFLAGS += $(SASL_CPPFLAGS)
endif
if USE_LDAP
opendkim_genzone_CPPFLAGS += $(OPENLDAP_CPPFLAGS)
opendkim_genzone_LDADD += $(OPENLDAP_LIBS)
endif
if LUA
opendkim_genzone_CPPFLAGS += $(LIBLUA_INCDIRS) $(LIBMILTER_INCDIRS)
opendkim_genzone_LDFLAGS += $(LIBLUA_LIBDIRS)
opendkim_genzone_LDADD += $(LIBLUA_LIBS)
endif

if ATPS
opendkim_atpszone_SOURCES = config.c config.h opendkim-db.c opendkim-db.h opendkim-atpszone.c opendkim-lua.c util.c util.h
opendkim_atpszone_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_atpszone_CFLAGS = $(COV_CFLAGS) $(LIBCRYPTO_CFLAGS)
opendkim_atpszone_LDFLAGS = $(COV_LDFLAGS) $(LIBCRYPTO_LIBDIRS)
opendkim_atpszone_LDADD = ../libopendkim/libopendkim.la $(COV_LIBADD) $(LIBCRYPTO_LIBS)
if USE_DB_OPENDKIM
opendkim_atpszone_CPPFLAGS += $(LIBDB_INCDIRS)
opendkim_atpszone_LDFLAGS += $(LIBDB_LIBDIRS)
opendkim_atpszone_LDADD += $(LIBDB_LIBS)
endif
if USE_ODBX
opendkim_atpszone_CPPFLAGS += $(LIBODBX_CPPFLAGS)
opendkim_atpszone_CFLAGS += $(LIBODBX_CFLAGS)
opendkim_atpszone_LDADD += $(LIBODBX_LIBS)
endif
if USE_SASL
opendkim_atpszone_CPPFLAGS += $(SASL_CPPFLAGS)
endif
if USE_LDAP
opendkim_atpszone_CPPFLAGS += $(OPENLDAP_CPPFLAGS)
opendkim_atpszone_LDADD += $(OPENLDAP_LIBS)
endif
if LUA
opendkim_atpszone_CPPFLAGS += $(LIBLUA_INCDIRS) $(LIBMILTER_INCDIRS)
opendkim_atpszone_LDFLAGS += $(LIBLUA_LIBDIRS)
opendkim_atpszone_LDADD += $(LIBLUA_LIBS)
endif
endif

if STATS
if USE_ODBX
opendkim_spam_SOURCES = config.c config.h opendkim-spam.c
opendkim_spam_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBODBX_CPPFLAGS)
opendkim_spam_CFLAGS = $(COV_CFLAGS) $(LIBODBX_CFLAGS)
opendkim_spam_LDFLAGS = $(COV_LDFLAGS) 
opendkim_spam_LDADD = ../libopendkim/libopendkim.la $(COV_LIBADD) $(LIBODBX_LIBS)
endif
endif

if LUA
dist_doc_DATA += \
        setup.lua.sample \
	screen.lua.sample \
	final.lua.sample
endif

man_MANS = opendkim-genkey.8 opendkim-genzone.8 opendkim-testadsp.8 \
	opendkim-testkey.8
if BUILD_FILTER
man_MANS += opendkim.conf.5 opendkim.8
if LUA
man_MANS += opendkim-lua.3
endif
endif
if STATS
man_MANS += opendkim-stats.8
endif
if ATPS
man_MANS += opendkim-atpszone.8
endif
if STATS
if USE_ODBX
man_MANS += opendkim-spam.1
endif
endif
