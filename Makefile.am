# $Id: Makefile.am,v 1.21 2010/01/14 05:58:38 cm-msk Exp $

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = 
if USE_ARLIB
SUBDIRS += libar
endif
if VBR
SUBDIRS += libvbr
endif
if LUA
SUBDIRS += miltertest opendkim/tests
endif
SUBDIRS += libopendkim libopendkim/tests opendkim
EXTRA_DIST = FEATURES KNOWNBUGS LICENSE LICENSE.Sendmail \
	RELEASE_NOTES.Sendmail \
	contrib/opendkim.init \
	contrib/opendkim.spec \
	docs/draft-ietf-dkim-deployment-10.txt \
	docs/draft-kucherawy-dkim-reporting-06.txt \
	docs/draft-shafranovich-feedback-report-08.txt \
	docs/rfc4686.txt \
	docs/rfc4871.txt \
	docs/rfc5016.txt \
	docs/rfc5451.txt \
	docs/rfc5518.txt \
	docs/rfc5585.txt \
	docs/rfc5617.txt \
	docs/rfc5672.txt \
	libopendkim/docs/dkim.html \
	libopendkim/docs/dkim_alg_t.html \
	libopendkim/docs/dkim_body.html \
	libopendkim/docs/dkim_canon_t.html \
	libopendkim/docs/dkim_cbstat.html \
	libopendkim/docs/dkim_chunk.html \
	libopendkim/docs/dkim_close.html \
	libopendkim/docs/dkim_dnssec.html \
	libopendkim/docs/dkim_eoh.html \
	libopendkim/docs/dkim_eom.html \
	libopendkim/docs/dkim_flush_cache.html \
	libopendkim/docs/dkim_free.html \
	libopendkim/docs/dkim_get_user_context.html \
	libopendkim/docs/dkim_getcachestats.html \
	libopendkim/docs/dkim_getdomain.html \
	libopendkim/docs/dkim_geterror.html \
	libopendkim/docs/dkim_getmode.html \
	libopendkim/docs/dkim_getpolicystr.html \
	libopendkim/docs/dkim_getpresult.html \
	libopendkim/docs/dkim_getpresultstr.html \
	libopendkim/docs/dkim_getresultstr.html \
	libopendkim/docs/dkim_getsighdr.html \
	libopendkim/docs/dkim_getsiglist.html \
	libopendkim/docs/dkim_getsignature.html \
	libopendkim/docs/dkim_header.html \
	libopendkim/docs/dkim_init.html \
	libopendkim/docs/dkim_key_syntax.html \
	libopendkim/docs/dkim_lib.html \
	libopendkim/docs/dkim_minbody.html \
	libopendkim/docs/dkim_ohdrs.html \
	libopendkim/docs/dkim_options.html \
	libopendkim/docs/dkim_param_t.html \
	libopendkim/docs/dkim_policy.html \
	libopendkim/docs/dkim_policy_getdnssec.html \
	libopendkim/docs/dkim_policy_getreportinfo.html \
	libopendkim/docs/dkim_policy_syntax.html \
	libopendkim/docs/dkim_policy_t.html \
	libopendkim/docs/dkim_presult.html \
	libopendkim/docs/dkim_pstate.html \
	libopendkim/docs/dkim_query_t.html \
	libopendkim/docs/dkim_set_dns_callback.html \
	libopendkim/docs/dkim_set_final.html \
	libopendkim/docs/dkim_set_key_lookup.html \
	libopendkim/docs/dkim_set_margin.html \
	libopendkim/docs/dkim_set_policy_lookup.html \
	libopendkim/docs/dkim_set_prescreen.html \
	libopendkim/docs/dkim_set_signature_handle.html \
	libopendkim/docs/dkim_set_signature_handle_free.html \
	libopendkim/docs/dkim_set_signature_tagvalues.html \
	libopendkim/docs/dkim_set_signer.html \
	libopendkim/docs/dkim_set_user_context.html \
	libopendkim/docs/dkim_sig_getbh.html \
	libopendkim/docs/dkim_sig_getcanonlen.html \
	libopendkim/docs/dkim_sig_getcontext.html \
	libopendkim/docs/dkim_sig_getdnssec.html \
	libopendkim/docs/dkim_sig_getdomain.html \
	libopendkim/docs/dkim_sig_geterror.html \
	libopendkim/docs/dkim_sig_geterrorstr.html \
	libopendkim/docs/dkim_sig_getflags.html \
	libopendkim/docs/dkim_sig_getkeysize.html \
	libopendkim/docs/dkim_sig_getreportinfo.html \
	libopendkim/docs/dkim_sig_getselector.html \
	libopendkim/docs/dkim_sig_getsignalg.html \
	libopendkim/docs/dkim_sig_getsigntime.html \
	libopendkim/docs/dkim_sig_hdrsigned.html \
	libopendkim/docs/dkim_sig_ignore.html \
	libopendkim/docs/dkim_sig_process.html \
	libopendkim/docs/dkim_sig_syntax.html \
	libopendkim/docs/dkim_sigerror.html \
	libopendkim/docs/dkim_siginfo.html \
	libopendkim/docs/dkim_sigkey_t.html \
	libopendkim/docs/dkim_sign.html \
	libopendkim/docs/dkim_ssl_version.html \
	libopendkim/docs/dkim_stat.html \
	libopendkim/docs/dkim_verify.html \
	libopendkim/docs/index.html \
	libopendkim/docs/overview.html \
	libopendkim/docs/dkim_mail_parse.html \
	libopendkim/docs/dkim_diffheaders.html \
	libopendkim/docs/dkim_get_msgdate.html \
	libopendkim/docs/dkim_getpartial.html \
	libopendkim/docs/dkim_get_reputation.html \
	libopendkim/docs/dkim_setpartial.html \
	libopendkim/docs/dkim_set_trust_anchor.html \
	libopendkim/docs/dkim_sig_getidentity.html \
	libopendkim/docs/dkim_sig_getcanons.html \
	libopendkim/docs/dkim_libfeature.html

# TODO: get configure.ac to generate --enable-{feature} for all
# non-experimental features and substitute it here e.g  @SUPPORTED_FEATURES@.
# Perhaps all features would enable a more comprehensive test coverage map
# though.
DISTCHECK_CONFIGURE_FLAGS=--enable-testcoverage --enable-arlib --enable-vbr

dist-hook:
	[ -f $(distdir)/libopendkim/dkim.h ] && rm -f  $(distdir)/libopendkim/dkim.h
	sed -e '/^#define[ \t]*OPENDKIM_LIB_VERSION/s/0x[0-9]*/0x@HEX_VERSION@/' < $(srcdir)/libopendkim/dkim.h > $(distdir)/libopendkim/dkim.h
	echo "looking to see if @VERSION@ is in the RELEASE_NOTES"
	fgrep @VERSION@ $(srcdir)/RELEASE_NOTES
	sed -e 's|\(@VERSION@[ \t]*\)[0-9?]\{4\}\(/[0-9?]\{2\}\)\{2\}|\1'`date +%Y/%m/%d`'|' < $(srcdir)/RELEASE_NOTES > $(distdir)/RELEASE_NOTES

push:
	@echo "Are you sure you want to tag and release $(distdir).tar.gz? (y/n)"
	@read confirm && [ $$confirm = 'y' ]
	cvs tag rel-opendkim-`echo $(VERSION) | sed 's/\./-/g'`
	sha1 $(distdir).tar.gz > $(distdir).tar.gz.sha1 || sha1sum  $(distdir).tar.gz > $(distdir).tar.gz.sha1
	md5 $(distdir).tar.gz > $(distdir).tar.gz.md5
	scp $(distdir).tar.gz $(distdir).tar.gz.sha1 $(distdir).tar.gz.md5 RELEASE_NOTES cm-msk,opendkim@frs.sourceforge.net:/home/frs/project/o/op/opendkim/

.PHONY: push
