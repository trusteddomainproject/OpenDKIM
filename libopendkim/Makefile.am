# $Id: Makefile.am,v 1.39 2009/11/13 20:16:45 cm-msk Exp $

lib_LTLIBRARIES = libopendkim.la
libopendkim_la_SOURCES = base64.c dkim-cache.c dkim-canon.c dkim-keys.c dkim-mailparse.c dkim-policy.c dkim-rep.c dkim-strl.c dkim-tables.c dkim-test.c dkim-ub.c dkim-util.c dkim.c util.c base64.h dkim-cache.h dkim-canon.h dkim-internal.h dkim-keys.h dkim-mailparse.h dkim-policy.h dkim-rep.h dkim-strl.h dkim-tables.h dkim-test.h dkim-types.h dkim-ub.h dkim-util.h dkim.h util.h
libopendkim_la_CFLAGS = $(LIBCRYPTO_INCDIRS)
libopendkim_la_LDFLAGS = $(LIBCRYPTO_LIBDIRS)
libopendkim_la_LIBADD = $(LIBCRYPTO_LIBS)
if !ALL_SYMBOLS
libopendkim_la_DEPENDENCIES = symbols.map
libopendkim_la_LDFLAGS += -export-symbols symbols.map
endif
if DEBUG
libopendkim_la_CFLAGS += -g
endif
libopendkimincludedir = $(includedir)/opendkim
libopendkiminclude_HEADERS = dkim.h
libopendkim_ladir = $(datadir)/opendkim
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

if DIFFHEADERS
libopendkim_la_CFLAGS += -D_FFR_DIFFHEADERS
endif

if DKIM_REPUTATION
libopendkim_la_CFLAGS += -D_FFR_DKIM_REPUTATION
endif

if DNS_UPGRADE
libopendkim_la_CFLAGS += -D_FFR_DNS_UPGRADE
endif

if PARSE_TIME
libopendkim_la_CFLAGS += -D_FFR_PARSE_TIME
endif

if QUERY_CACHE
libopendkim_la_CFLAGS += -DQUERY_CACHE
endif

if STATS
libopendkim_la_CFLAGS += -D_FFR_STATS
endif

if USE_ARLIB
libopendkim_la_CFLAGS += -DUSE_ARLIB -I../libar
libopendkim_la_LIBADD += ../libar/libar.la
endif

if USE_DB_LIBOPENDKIM
libopendkim_la_CFLAGS += -DUSE_DB -I$(LIBDB_INCDIRS)
libopendkim_la_LDFLAGS += $(LIBDB_LIBDIRS)
libopendkim_la_LIBADD += $(LIBDB_LIBS)
endif

if USE_TRE
libopendkim_la_CFLAGS += -DUSE_TRE
libopendkim_la_CFLAGS += $(LIBTRE_INCDIRS)
libopendkim_la_LDFLAGS += $(LIBTRE_LIBDIRS)
libopendkim_la_LIBADD += $(LIBTRE_LIBS)
endif

if USE_UNBOUND
libopendkim_la_CFLAGS += -DUSE_UNBOUND
libopendkim_la_CFLAGS += $(LIBUNBOUND_INCDIRS)
libopendkim_la_LDFLAGS += $(LIBUNBOUND_LIBDIRS)
libopendkim_la_LIBADD += $(LIBUNBOUND_LIBS)
endif

check_PROGRAMS = t-setup t-test00 t-test01 t-test02 t-test03 t-test04 \
	t-test05 t-test06 t-test07 t-test08 t-test09 t-test10 t-test11 \
	t-test12 t-test13 t-test14 t-test15 t-test16 t-test17 t-test18 \
	t-test19 t-test20 t-test21 t-test22 t-test23 t-test24 t-test25 \
	t-test26 t-test27 t-test28 t-test29 t-test30 t-test31 t-test32 \
	t-test33 t-test34 t-test35 t-test36 t-test37 t-test38 t-test39 \
	t-test40 t-test41 t-test42 t-test43 t-test44 t-test45 t-test46 \
	t-test47 t-test48 t-test49 t-test50 t-test51 t-test52 t-test53 \
	t-test54 t-test55 t-test56 t-test57 t-test58 t-test59 t-test60 \
	t-test61 t-test62 t-test63 t-test64 t-test65 t-test66 t-test67 \
	t-test68 t-test69 t-test70 t-test71 t-test72 t-test73 t-test74 \
	t-test75 t-test76 t-test77 t-test78 t-test79 t-test80 t-test81 \
	t-test82 t-test83 t-test84 t-test85 t-test86 t-test87 t-test88 \
	t-test89 t-test90 t-test91 t-test92 t-test93 t-test94 t-test95 \
	t-test96 t-test97 t-test98 t-test99 t-test100 t-test101 t-test102 \
	t-test103 t-test104 t-test105 t-test106 t-test107 t-test108 \
	t-test109 t-test110 t-test111 t-test112 t-test114 \
	t-test115 t-test116 t-test117 t-test119 t-test120 \
	t-test121 t-test122 t-test123 t-test124 t-test125 t-test126 \
	t-test127 t-test130 t-test131 t-signperf t-verifyperf
if ALL_SYMBOLS
check_PROGRAMS += t-test113 t-test118
endif
check_PROGRAMS += t-cleanup
TESTS = $(check_PROGRAMS)

t_setup_SOURCES = t-setup.c t-testdata.h
t_setup_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_setup_LDADD = ./libopendkim.la
if DEBUG
t_setup_CFLAGS = -g
endif

t_cleanup_SOURCES = t-cleanup.c t-testdata.h
t_cleanup_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_cleanup_LDADD = ./libopendkim.la
if DEBUG
t_cleanup_CFLAGS = -g
endif

t_signperf_SOURCES = t-signperf.c t-testdata.h
t_signperf_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_signperf_LDADD = ./libopendkim.la
if DEBUG
t_signperf_CFLAGS = -g
endif

t_verifyperf_SOURCES = t-verifyperf.c t-testdata.h
t_verifyperf_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_verifyperf_LDADD = ./libopendkim.la
if DEBUG
t_verifyperf_CFLAGS = -g
endif

t_test00_SOURCES = t-test00.c t-testdata.h
t_test00_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test00_LDADD = ./libopendkim.la
if DEBUG
t_test00_CFLAGS = -g
endif

t_test01_SOURCES = t-test01.c t-testdata.h
t_test01_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test01_LDADD = ./libopendkim.la
if DEBUG
t_test01_CFLAGS = -g
endif

t_test02_SOURCES = t-test02.c t-testdata.h
t_test02_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test02_LDADD = ./libopendkim.la
if DEBUG
t_test02_CFLAGS = -g
endif

t_test03_SOURCES = t-test03.c t-testdata.h
t_test03_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test03_LDADD = ./libopendkim.la
if DEBUG
t_test03_CFLAGS = -g
endif

t_test04_SOURCES = t-test04.c t-testdata.h
t_test04_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test04_LDADD = ./libopendkim.la
if DEBUG
t_test04_CFLAGS = -g
endif

t_test05_SOURCES = t-test05.c t-testdata.h
t_test05_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test05_LDADD = ./libopendkim.la
if DEBUG
t_test05_CFLAGS = -g
endif

t_test06_SOURCES = t-test06.c t-testdata.h
t_test06_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test06_LDADD = ./libopendkim.la
if DEBUG
t_test06_CFLAGS = -g
endif

t_test07_SOURCES = t-test07.c t-testdata.h
t_test07_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test07_LDADD = ./libopendkim.la
if DEBUG
t_test07_CFLAGS = -g
endif

t_test08_SOURCES = t-test08.c t-testdata.h
t_test08_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test08_LDADD = ./libopendkim.la
if DEBUG
t_test08_CFLAGS = -g
endif

t_test09_SOURCES = t-test09.c t-testdata.h
t_test09_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test09_LDADD = ./libopendkim.la
if DEBUG
t_test09_CFLAGS = -g
endif

t_test10_SOURCES = t-test10.c t-testdata.h
t_test10_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test10_LDADD = ./libopendkim.la
if DEBUG
t_test10_CFLAGS = -g
endif

t_test11_SOURCES = t-test11.c t-testdata.h
t_test11_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test11_LDADD = ./libopendkim.la
if DEBUG
t_test11_CFLAGS = -g
endif

t_test12_SOURCES = t-test12.c t-testdata.h
t_test12_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test12_LDADD = ./libopendkim.la
if DEBUG
t_test12_CFLAGS = -g
endif

t_test13_SOURCES = t-test13.c t-testdata.h
t_test13_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test13_LDADD = ./libopendkim.la
if DEBUG
t_test13_CFLAGS = -g
endif

t_test14_SOURCES = t-test14.c t-testdata.h
t_test14_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test14_LDADD = ./libopendkim.la
if DEBUG
t_test14_CFLAGS = -g
endif

t_test15_SOURCES = t-test15.c t-testdata.h
t_test15_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test15_LDADD = ./libopendkim.la
if DEBUG
t_test15_CFLAGS = -g
endif

t_test16_SOURCES = t-test16.c t-testdata.h
t_test16_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test16_LDADD = ./libopendkim.la
if DEBUG
t_test16_CFLAGS = -g
endif

t_test17_SOURCES = t-test17.c t-testdata.h
t_test17_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test17_LDADD = ./libopendkim.la
if DEBUG
t_test17_CFLAGS = -g
endif

t_test18_SOURCES = t-test18.c t-testdata.h
t_test18_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test18_LDADD = ./libopendkim.la
if DEBUG
t_test18_CFLAGS = -g
endif

t_test19_SOURCES = t-test19.c t-testdata.h
t_test19_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test19_LDADD = ./libopendkim.la
if DEBUG
t_test19_CFLAGS = -g
endif

t_test20_SOURCES = t-test20.c t-testdata.h
t_test20_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test20_LDADD = ./libopendkim.la
if DEBUG
t_test20_CFLAGS = -g
endif

t_test21_SOURCES = t-test21.c t-testdata.h
t_test21_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test21_LDADD = ./libopendkim.la
if DEBUG
t_test21_CFLAGS = -g
endif

t_test22_SOURCES = t-test22.c t-testdata.h
t_test22_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test22_LDADD = ./libopendkim.la
if DEBUG
t_test22_CFLAGS = -g
endif

t_test23_SOURCES = t-test23.c t-testdata.h
t_test23_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test23_LDADD = ./libopendkim.la
if DEBUG
t_test23_CFLAGS = -g
endif

t_test24_SOURCES = t-test24.c t-testdata.h
t_test24_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test24_LDADD = ./libopendkim.la
if DEBUG
t_test24_CFLAGS = -g
endif

t_test25_SOURCES = t-test25.c t-testdata.h
t_test25_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test25_LDADD = ./libopendkim.la
if DEBUG
t_test25_CFLAGS = -g
endif

t_test26_SOURCES = t-test26.c t-testdata.h
t_test26_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test26_LDADD = ./libopendkim.la
if DEBUG
t_test26_CFLAGS = -g
endif

t_test27_SOURCES = t-test27.c t-testdata.h
t_test27_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test27_LDADD = ./libopendkim.la
if DEBUG
t_test27_CFLAGS = -g
endif

t_test28_SOURCES = t-test28.c t-testdata.h
t_test28_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test28_LDADD = ./libopendkim.la
if DEBUG
t_test28_CFLAGS = -g
endif

t_test29_SOURCES = t-test29.c t-testdata.h
t_test29_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test29_LDADD = ./libopendkim.la
if DEBUG
t_test29_CFLAGS = -g
endif

t_test30_SOURCES = t-test30.c t-testdata.h
t_test30_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test30_LDADD = ./libopendkim.la
if DEBUG
t_test30_CFLAGS = -g
endif

t_test31_SOURCES = t-test31.c t-testdata.h
t_test31_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test31_LDADD = ./libopendkim.la
if DEBUG
t_test31_CFLAGS = -g
endif

t_test32_SOURCES = t-test32.c t-testdata.h
t_test32_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test32_LDADD = ./libopendkim.la
if DEBUG
t_test32_CFLAGS = -g
endif

t_test33_SOURCES = t-test33.c t-testdata.h
t_test33_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test33_LDADD = ./libopendkim.la
if DEBUG
t_test33_CFLAGS = -g
endif

t_test34_SOURCES = t-test34.c t-testdata.h
t_test34_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test34_LDADD = ./libopendkim.la
if DEBUG
t_test34_CFLAGS = -g
endif

t_test35_SOURCES = t-test35.c t-testdata.h
t_test35_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test35_LDADD = ./libopendkim.la
if DEBUG
t_test35_CFLAGS = -g
endif

t_test36_SOURCES = t-test36.c t-testdata.h
t_test36_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test36_LDADD = ./libopendkim.la
if DEBUG
t_test36_CFLAGS = -g
endif

t_test37_SOURCES = t-test37.c t-testdata.h
t_test37_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test37_LDADD = ./libopendkim.la
if DEBUG
t_test37_CFLAGS = -g
endif

t_test38_SOURCES = t-test38.c t-testdata.h
t_test38_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test38_LDADD = ./libopendkim.la
if DEBUG
t_test38_CFLAGS = -g
endif

t_test39_SOURCES = t-test39.c t-testdata.h
t_test39_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test39_LDADD = ./libopendkim.la
if DEBUG
t_test39_CFLAGS = -g
endif

t_test40_SOURCES = t-test40.c t-testdata.h
t_test40_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test40_LDADD = ./libopendkim.la
if DEBUG
t_test40_CFLAGS = -g
endif

t_test41_SOURCES = t-test41.c t-testdata.h
t_test41_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test41_LDADD = ./libopendkim.la
if DEBUG
t_test41_CFLAGS = -g
endif

t_test42_SOURCES = t-test42.c t-testdata.h
t_test42_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test42_LDADD = ./libopendkim.la
if DEBUG
t_test42_CFLAGS = -g
endif

t_test43_SOURCES = t-test43.c t-testdata.h
t_test43_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test43_LDADD = ./libopendkim.la
if DEBUG
t_test43_CFLAGS = -g
endif

t_test44_SOURCES = t-test44.c t-testdata.h
t_test44_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test44_LDADD = ./libopendkim.la
if DEBUG
t_test44_CFLAGS = -g
endif

t_test45_SOURCES = t-test45.c t-testdata.h
t_test45_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test45_LDADD = ./libopendkim.la
if DEBUG
t_test45_CFLAGS = -g
endif

t_test46_SOURCES = t-test46.c t-testdata.h
t_test46_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test46_LDADD = ./libopendkim.la
if DEBUG
t_test46_CFLAGS = -g
endif

t_test47_SOURCES = t-test47.c t-testdata.h
t_test47_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test47_LDADD = ./libopendkim.la
if DEBUG
t_test47_CFLAGS = -g
endif

t_test48_SOURCES = t-test48.c t-testdata.h
t_test48_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test48_LDADD = ./libopendkim.la
if DEBUG
t_test48_CFLAGS = -g
endif

t_test49_SOURCES = t-test49.c t-testdata.h
t_test49_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test49_LDADD = ./libopendkim.la
if DEBUG
t_test49_CFLAGS = -g
endif

t_test50_SOURCES = t-test50.c t-testdata.h
t_test50_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test50_LDADD = ./libopendkim.la
if DEBUG
t_test50_CFLAGS = -g
endif

t_test51_SOURCES = t-test51.c t-testdata.h
t_test51_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test51_LDADD = ./libopendkim.la
if DEBUG
t_test51_CFLAGS = -g
endif

t_test52_SOURCES = t-test52.c t-testdata.h
t_test52_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test52_LDADD = ./libopendkim.la
if DEBUG
t_test52_CFLAGS = -g
endif

t_test53_SOURCES = t-test53.c t-testdata.h
t_test53_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test53_LDADD = ./libopendkim.la
if DEBUG
t_test53_CFLAGS = -g
endif

t_test54_SOURCES = t-test54.c t-testdata.h
t_test54_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test54_LDADD = ./libopendkim.la
if DEBUG
t_test54_CFLAGS = -g
endif

t_test55_SOURCES = t-test55.c t-testdata.h
t_test55_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test55_LDADD = ./libopendkim.la
if DEBUG
t_test55_CFLAGS = -g
endif

t_test56_SOURCES = t-test56.c t-testdata.h
t_test56_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test56_LDADD = ./libopendkim.la
if DEBUG
t_test56_CFLAGS = -g
endif

t_test57_SOURCES = t-test57.c t-testdata.h
t_test57_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test57_LDADD = ./libopendkim.la
if DEBUG
t_test57_CFLAGS = -g
endif

t_test58_SOURCES = t-test58.c t-testdata.h
t_test58_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test58_LDADD = ./libopendkim.la
if DEBUG
t_test58_CFLAGS = -g
endif

t_test59_SOURCES = t-test59.c t-testdata.h
t_test59_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test59_LDADD = ./libopendkim.la
if DEBUG
t_test59_CFLAGS = -g
endif

t_test60_SOURCES = t-test60.c t-testdata.h
t_test60_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test60_LDADD = ./libopendkim.la
if DEBUG
t_test60_CFLAGS = -g
endif

t_test61_SOURCES = t-test61.c t-testdata.h
t_test61_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test61_LDADD = ./libopendkim.la
if DEBUG
t_test61_CFLAGS = -g
endif

t_test62_SOURCES = t-test62.c t-testdata.h
t_test62_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test62_LDADD = ./libopendkim.la
if DEBUG
t_test62_CFLAGS = -g
endif

t_test63_SOURCES = t-test63.c t-testdata.h
t_test63_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test63_LDADD = ./libopendkim.la
if DEBUG
t_test63_CFLAGS = -g
endif

t_test64_SOURCES = t-test64.c t-testdata.h
t_test64_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test64_LDADD = ./libopendkim.la
if DEBUG
t_test64_CFLAGS = -g
endif

t_test65_SOURCES = t-test65.c t-testdata.h
t_test65_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test65_LDADD = ./libopendkim.la
if DEBUG
t_test65_CFLAGS = -g
endif

t_test66_SOURCES = t-test66.c t-testdata.h
t_test66_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test66_LDADD = ./libopendkim.la
if DEBUG
t_test66_CFLAGS = -g
endif

t_test67_SOURCES = t-test67.c t-testdata.h
t_test67_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test67_LDADD = ./libopendkim.la
if DEBUG
t_test67_CFLAGS = -g
endif

t_test68_SOURCES = t-test68.c t-testdata.h
t_test68_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test68_LDADD = ./libopendkim.la
if DEBUG
t_test68_CFLAGS = -g
endif

t_test69_SOURCES = t-test69.c t-testdata.h
t_test69_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test69_LDADD = ./libopendkim.la
if DEBUG
t_test69_CFLAGS = -g
endif

t_test70_SOURCES = t-test70.c t-testdata.h
t_test70_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test70_LDADD = ./libopendkim.la
if DEBUG
t_test70_CFLAGS = -g
endif

t_test71_SOURCES = t-test71.c t-testdata.h
t_test71_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test71_LDADD = ./libopendkim.la
if DEBUG
t_test71_CFLAGS = -g
endif

t_test72_SOURCES = t-test72.c t-testdata.h
t_test72_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test72_LDADD = ./libopendkim.la
if DEBUG
t_test72_CFLAGS = -g
endif

t_test73_SOURCES = t-test73.c t-testdata.h
t_test73_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test73_LDADD = ./libopendkim.la
if DEBUG
t_test73_CFLAGS = -g
endif

t_test74_SOURCES = t-test74.c t-testdata.h
t_test74_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test74_LDADD = ./libopendkim.la
if DEBUG
t_test74_CFLAGS = -g
endif

t_test75_SOURCES = t-test75.c t-testdata.h
t_test75_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test75_LDADD = ./libopendkim.la
if DEBUG
t_test75_CFLAGS = -g
endif

t_test76_SOURCES = t-test76.c t-testdata.h
t_test76_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test76_LDADD = ./libopendkim.la
if DEBUG
t_test76_CFLAGS = -g
endif

t_test77_SOURCES = t-test77.c t-testdata.h
t_test77_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test77_LDADD = ./libopendkim.la
if DEBUG
t_test77_CFLAGS = -g
endif

t_test78_SOURCES = t-test78.c t-testdata.h
t_test78_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test78_LDADD = ./libopendkim.la
if DEBUG
t_test78_CFLAGS = -g
endif

t_test79_SOURCES = t-test79.c t-testdata.h
t_test79_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test79_LDADD = ./libopendkim.la
if DEBUG
t_test79_CFLAGS = -g
endif

t_test80_SOURCES = t-test80.c t-testdata.h
t_test80_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test80_LDADD = ./libopendkim.la
if DEBUG
t_test80_CFLAGS = -g
endif

t_test81_SOURCES = t-test81.c t-testdata.h
t_test81_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test81_LDADD = ./libopendkim.la
if DEBUG
t_test81_CFLAGS = -g
endif

t_test82_SOURCES = t-test82.c t-testdata.h
t_test82_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test82_LDADD = ./libopendkim.la
if DEBUG
t_test82_CFLAGS = -g
endif

t_test83_SOURCES = t-test83.c t-testdata.h
t_test83_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test83_LDADD = ./libopendkim.la
if DEBUG
t_test83_CFLAGS = -g
endif

t_test84_SOURCES = t-test84.c t-testdata.h
t_test84_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test84_LDADD = ./libopendkim.la
if DEBUG
t_test84_CFLAGS = -g
endif

t_test85_SOURCES = t-test85.c t-testdata.h
t_test85_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test85_LDADD = ./libopendkim.la
if DEBUG
t_test85_CFLAGS = -g
endif

t_test86_SOURCES = t-test86.c t-testdata.h
t_test86_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test86_LDADD = ./libopendkim.la
if DEBUG
t_test86_CFLAGS = -g
endif

t_test87_SOURCES = t-test87.c t-testdata.h
t_test87_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test87_LDADD = ./libopendkim.la
if DEBUG
t_test87_CFLAGS = -g
endif

t_test88_SOURCES = t-test88.c t-testdata.h
t_test88_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test88_LDADD = ./libopendkim.la
if DEBUG
t_test88_CFLAGS = -g
endif

t_test89_SOURCES = t-test89.c t-testdata.h
t_test89_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test89_LDADD = ./libopendkim.la
if DEBUG
t_test89_CFLAGS = -g
endif

t_test90_SOURCES = t-test90.c t-testdata.h
t_test90_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test90_LDADD = ./libopendkim.la
if DEBUG
t_test90_CFLAGS = -g
endif

t_test91_SOURCES = t-test91.c t-testdata.h
t_test91_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test91_LDADD = ./libopendkim.la
if DEBUG
t_test91_CFLAGS = -g
endif

t_test92_SOURCES = t-test92.c t-testdata.h
t_test92_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test92_LDADD = ./libopendkim.la
if DEBUG
t_test92_CFLAGS = -g
endif

t_test93_SOURCES = t-test93.c t-testdata.h
t_test93_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test93_LDADD = ./libopendkim.la
if DEBUG
t_test93_CFLAGS = -g
endif

t_test94_SOURCES = t-test94.c t-testdata.h
t_test94_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test94_LDADD = ./libopendkim.la
if DEBUG
t_test94_CFLAGS = -g
endif

t_test95_SOURCES = t-test95.c t-testdata.h
t_test95_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test95_LDADD = ./libopendkim.la
if DEBUG
t_test95_CFLAGS = -g
endif

t_test96_SOURCES = t-test96.c t-testdata.h
t_test96_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test96_LDADD = ./libopendkim.la
if DEBUG
t_test96_CFLAGS = -g
endif

t_test97_SOURCES = t-test97.c t-testdata.h
t_test97_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test97_LDADD = ./libopendkim.la
if DEBUG
t_test97_CFLAGS = -g
endif

t_test98_SOURCES = t-test98.c t-testdata.h
t_test98_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test98_LDADD = ./libopendkim.la
if DEBUG
t_test98_CFLAGS = -g
endif

t_test99_SOURCES = t-test99.c t-testdata.h
t_test99_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test99_LDADD = ./libopendkim.la
if DEBUG
t_test99_CFLAGS = -g
endif

t_test100_SOURCES = t-test100.c t-testdata.h
t_test100_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test100_LDADD = ./libopendkim.la
if DEBUG
t_test100_CFLAGS = -g
endif

t_test101_SOURCES = t-test101.c t-testdata.h
t_test101_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test101_LDADD = ./libopendkim.la
if DEBUG
t_test101_CFLAGS = -g
endif

t_test102_SOURCES = t-test102.c t-testdata.h
t_test102_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test102_LDADD = ./libopendkim.la
if DEBUG
t_test102_CFLAGS = -g
endif

t_test103_SOURCES = t-test103.c t-testdata.h
t_test103_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test103_LDADD = ./libopendkim.la
if DEBUG
t_test103_CFLAGS = -g
endif

t_test104_SOURCES = t-test104.c t-testdata.h
t_test104_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test104_LDADD = ./libopendkim.la
if DEBUG
t_test104_CFLAGS = -g
endif

t_test105_SOURCES = t-test105.c t-testdata.h
t_test105_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test105_LDADD = ./libopendkim.la
if DEBUG
t_test105_CFLAGS = -g
endif

t_test106_SOURCES = t-test106.c t-testdata.h
t_test106_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test106_LDADD = ./libopendkim.la
if DEBUG
t_test106_CFLAGS = -g
endif

t_test107_SOURCES = t-test107.c t-testdata.h
t_test107_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test107_LDADD = ./libopendkim.la
if DEBUG
t_test107_CFLAGS = -g
endif

t_test108_SOURCES = t-test108.c t-testdata.h
t_test108_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test108_LDADD = ./libopendkim.la
if DEBUG
t_test108_CFLAGS = -g
endif

t_test109_SOURCES = t-test109.c t-testdata.h
t_test109_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test109_LDADD = ./libopendkim.la
if DEBUG
t_test109_CFLAGS = -g
endif

t_test110_SOURCES = t-test110.c t-testdata.h
t_test110_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test110_LDADD = ./libopendkim.la
if DEBUG
t_test110_CFLAGS = -g
endif

t_test111_SOURCES = t-test111.c t-testdata.h
t_test111_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test111_LDADD = ./libopendkim.la
if DEBUG
t_test111_CFLAGS = -g
endif

t_test112_SOURCES = t-test112.c t-testdata.h
t_test112_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test112_LDADD = ./libopendkim.la
if DEBUG
t_test112_CFLAGS = -g
endif

if ALL_SYMBOLS
t_test113_SOURCES = t-test113.c t-testdata.h
t_test113_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test113_LDADD = ./libopendkim.la
if DEBUG
t_test113_CFLAGS = -g
endif
endif

t_test114_SOURCES = t-test114.c t-testdata.h
t_test114_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test114_LDADD = ./libopendkim.la
if DEBUG
t_test114_CFLAGS = -g
endif

t_test115_SOURCES = t-test115.c t-testdata.h
t_test115_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test115_LDADD = ./libopendkim.la
t_test115_CFLAGS = $(LIBCRYPTO_INCDIRS)
if DEBUG
t_test115_CFLAGS += -g
endif

t_test116_SOURCES = t-test116.c t-testdata.h
t_test116_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test116_LDADD = ./libopendkim.la
if DEBUG
t_test116_CFLAGS = -g
endif

t_test117_SOURCES = t-test117.c t-testdata.h
t_test117_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test117_LDADD = ./libopendkim.la
if DEBUG
t_test117_CFLAGS = -g
endif

if ALL_SYMBOLS
t_test118_SOURCES = t-test118.c t-testdata.h
t_test118_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test118_LDADD = ./libopendkim.la
if DEBUG
t_test118_CFLAGS = -g
endif
endif

t_test119_SOURCES = t-test119.c t-testdata.h
t_test119_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test119_LDADD = ./libopendkim.la
if DEBUG
t_test119_CFLAGS = -g
endif

t_test120_SOURCES = t-test120.c t-testdata.h
t_test120_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test120_LDADD = ./libopendkim.la
if DEBUG
t_test120_CFLAGS = -g
endif

t_test121_SOURCES = t-test121.c t-testdata.h
t_test121_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test121_LDADD = ./libopendkim.la
if DEBUG
t_test121_CFLAGS = -g
endif

t_test122_SOURCES = t-test122.c t-testdata.h
t_test122_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test122_LDADD = ./libopendkim.la
if DEBUG
t_test122_CFLAGS = -g
endif

t_test123_SOURCES = t-test123.c t-testdata.h
t_test123_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test123_LDADD = ./libopendkim.la
if DEBUG
t_test123_CFLAGS = -g
endif

t_test124_SOURCES = t-test124.c t-testdata.h
t_test124_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test124_LDADD = ./libopendkim.la
if DEBUG
t_test124_CFLAGS = -g
endif

t_test125_SOURCES = t-test125.c t-testdata.h
t_test125_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test125_LDADD = ./libopendkim.la
if DEBUG
t_test125_CFLAGS = -g
endif

t_test126_SOURCES = t-test126.c t-testdata.h
t_test126_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test126_LDADD = ./libopendkim.la
if DEBUG
t_test126_CFLAGS = -g
endif

t_test127_SOURCES = t-test127.c t-testdata.h
t_test127_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test127_LDADD = ./libopendkim.la
if DEBUG
t_test127_CFLAGS = -g
endif

t_test131_SOURCES = t-test131.c t-testdata.h
t_test131_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test131_LDADD = ./libopendkim.la
if DEBUG
t_test131_CFLAGS = -g
endif

t_test130_SOURCES = t-test130.c t-testdata.h
t_test130_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test130_LDADD = ./libopendkim.la
if DEBUG
t_test130_CFLAGS = -g
endif

t_test131_SOURCES = t-test131.c t-testdata.h
t_test131_LDFLAGS = -L. $(LIBCRYPTO_LIBDIRS)
t_test131_LDADD = ./libopendkim.la
if DEBUG
t_test131_CFLAGS = -g
endif

symbols.map: $(libopendkiminclude_HEADERS) 
	grep '^extern' $? | \
		awk '{ for (c = 1; c <= NF; c++) if ($$c ~ /dkim_/) { print $$c; break; } }' | \
		sed -e s/\[\*\;\]//g -e s/\[\\\[\\\]\]//g | \
		sort -u -o $@
