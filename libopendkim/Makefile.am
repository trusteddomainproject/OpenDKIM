# $Id: Makefile.am,v 1.47 2010/03/01 21:10:01 cm-msk Exp $

if DEBUG
AM_CFLAGS = -g
endif
LDADD = ./libopendkim.la

lib_LTLIBRARIES = libopendkim.la
libopendkim_la_SOURCES = base64.c dkim-cache.c dkim-canon.c dkim-keys.c dkim-mailparse.c dkim-policy.c dkim-rep.c dkim-strl.c dkim-tables.c dkim-test.c dkim-ub.c dkim-util.c dkim.c util.c base64.h dkim-cache.h dkim-canon.h dkim-internal.h dkim-keys.h dkim-mailparse.h dkim-policy.h dkim-rep.h dkim-strl.h dkim-tables.h dkim-test.h dkim-types.h dkim-ub.h dkim-util.h dkim.h util.h
libopendkim_la_CFLAGS = $(LIBOPENDKIM_INC) $(PTHREAD_CFLAGS) $(COV_CFLAGS)
libopendkim_la_CC = $(PTHREAD_CC)
libopendkim_la_LDFLAGS = -no-undefined  $(LIBCRYPTO_LIBDIRS) $(PTHREAD_CFLAGS) $(COV_LDFLAGS) -version-info $(LIBOPENDKIM_VERSION_INFO)
libopendkim_la_LIBADD = $(LIBOPENDKIM_LIBS) $(PTHREAD_LIBS) $(COV_LIBADD)
if !ALL_SYMBOLS
libopendkim_la_DEPENDENCIES = symbols.map
libopendkim_la_LDFLAGS += -export-symbols symbols.map
endif
libopendkim_includedir = $(includedir)/opendkim
libopendkim_include_HEADERS = dkim.h

libopendkim_ladir = $(docdir)
libopendkim_la_DATA = docs/dkim.html docs/dkim_alg_t.html docs/dkim_body.html \
	docs/dkim_canon_t.html docs/dkim_cbstat.html docs/dkim_chunk.html \
	docs/dkim_close.html docs/dkim_dnssec.html docs/dkim_eoh.html \
	docs/dkim_eom.html docs/dkim_flush_cache.html docs/dkim_free.html \
	docs/dkim_get_user_context.html docs/dkim_getcachestats.html \
	docs/dkim_getdomain.html docs/dkim_geterror.html \
	docs/dkim_getmode.html docs/dkim_getpolicystr.html \
	docs/dkim_getpresult.html docs/dkim_getpresultstr.html \
	docs/dkim_getresultstr.html docs/dkim_getsighdr.html \
	docs/dkim_getsiglist.html docs/dkim_getsignature.html \
	docs/dkim_header.html docs/dkim_init.html docs/dkim_key_syntax.html \
	docs/dkim_lib.html docs/dkim_minbody.html docs/dkim_ohdrs.html \
	docs/dkim_options.html docs/dkim_param_t.html docs/dkim_policy.html \
	docs/dkim_policy_getdnssec.html docs/dkim_policy_getreportinfo.html \
	docs/dkim_policy_syntax.html docs/dkim_policy_t.html \
	docs/dkim_presult.html docs/dkim_pstate.html docs/dkim_query_t.html \
	docs/dkim_set_dns_callback.html docs/dkim_set_final.html \
	docs/dkim_set_key_lookup.html docs/dkim_set_margin.html \
	docs/dkim_set_policy_lookup.html docs/dkim_set_prescreen.html \
	docs/dkim_set_signature_handle.html \
	docs/dkim_set_signature_handle_free.html \
	docs/dkim_set_signature_tagvalues.html docs/dkim_set_signer.html \
	docs/dkim_set_user_context.html docs/dkim_sig_getbh.html \
	docs/dkim_sig_getcanonlen.html docs/dkim_sig_getcontext.html \
	docs/dkim_sig_getdnssec.html docs/dkim_sig_getdomain.html \
	docs/dkim_sig_geterror.html docs/dkim_sig_geterrorstr.html \
	docs/dkim_sig_getflags.html docs/dkim_sig_getkeysize.html \
	docs/dkim_sig_getreportinfo.html docs/dkim_sig_getselector.html \
	docs/dkim_sig_getsignalg.html docs/dkim_sig_getsigntime.html \
	docs/dkim_sig_hdrsigned.html docs/dkim_sig_ignore.html \
	docs/dkim_sig_process.html docs/dkim_sig_syntax.html \
	docs/dkim_sigerror.html docs/dkim_siginfo.html \
	docs/dkim_sigkey_t.html docs/dkim_sign.html \
	docs/dkim_ssl_version.html docs/dkim_stat.html docs/dkim_verify.html \
	docs/index.html docs/overview.html docs/dkim_mail_parse.html \
	docs/dkim_diffheaders.html docs/dkim_get_msgdate.html \
	docs/dkim_getpartial.html docs/dkim_get_reputation.html \
	docs/dkim_setpartial.html docs/dkim_set_trust_anchor.html \
	docs/dkim_sig_getidentity.html docs/dkim_sig_getcanons.html \
	docs/dkim_libfeature.html

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = opendkim.pc

if USE_ARLIB
libopendkim_la_CFLAGS += -I$(srcdir)/../libar
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
libopendkim_la_CFLAGS += $(LIBUNBOUND_INCDIRS)
libopendkim_la_LDFLAGS += $(LIBUNBOUND_LIBDIRS)
libopendkim_la_LIBADD += $(LIBUNBOUND_LIBS)
endif

DISTCLEANFILES=symbols.map

symbols.map: $(libopendkim_include_HEADERS)
	grep '^extern' $? | \
		awk '{ for (c = 1; c <= NF; c++) if ($$c ~ /dkim_/) { print $$c; break; } }' | \
		sed -e s/\[\*\;\]//g -e s/\[\\\[\\\]\]//g | \
		sort -u -o $@

MOSTLYCLEANFILES=symbols.map
