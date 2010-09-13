# $Id: Makefile.am,v 1.29 2010/09/13 04:37:58 grooverdan Exp $

check_SCRIPTS = t-sign-ss t-sign-rs t-sign-rs-tables t-sign-rs-tables-bad \
	t-sign-rs-tables-token t-sign-rs-multiple t-sign-rs-mixconf \
	t-sign-rs-lua t-sign-ss-all \
	t-verify-revoked t-verify-unspec \
	t-verify-unsigned t-verify-unsigned-silent \
	t-verify-syntax t-verify-ss t-verify-ss-bad \
	t-dontsign t-peer t-verify-report

TESTS = $(check_SCRIPTS)

EXTRA_DIST = \
	t-sign-rs t-sign-rs.conf t-sign-rs.lua \
	t-sign-rs-lua t-sign-rs-lua.conf t-sign-rs-lua.keys \
		t-sign-rs-lua.lua t-sign-rs-lua.lua-setup t-sign-rs-lua.sign \
	t-sign-rs-mixconf t-sign-rs-mixconf.keys t-sign-rs-mixconf.conf \
		t-sign-rs-mixconf.lua t-sign-rs-mixconf.lua-setup \
	t-sign-rs-multiple t-sign-rs-multiple.conf t-sign-rs-multiple.keys \
		t-sign-rs-multiple.lua t-sign-rs-multiple.sign \
	t-sign-rs-tables t-sign-rs-tables.conf t-sign-rs-tables.keys \
		t-sign-rs-tables.lua t-sign-rs-tables.sign \
	t-sign-rs-tables-bad t-sign-rs-tables-bad.conf \
		t-sign-rs-tables-bad.keys t-sign-rs-tables-bad.lua \
	t-sign-rs-tables-token t-sign-rs-tables-token.conf \
		t-sign-rs-tables-token.keys t-sign-rs-tables-token.lua \
	t-sign-ss t-sign-ss.conf t-sign-ss.lua \
	t-sign-ss-all t-sign-ss-all.conf t-sign-ss-all.lua \
	t-sign-ss-macro t-sign-ss-macro.conf t-sign-ss-macro.lua \
	t-verify-revoked t-verify-revoked.conf t-verify-revoked.lua \
	t-verify-unsigned t-verify-unsigned.conf t-verify-unsigned.lua \
	t-verify-unsigned-silent t-verify-unsigned-silent.conf \
		t-verify-unsigned-silent.lua \
	t-verify-unspec t-verify-unspec.conf t-verify-unspec.lua \
	t-verify-ss t-verify-ss.conf t-verify-ss.lua \
	t-verify-ss-bad t-verify-ss-bad.conf t-verify-ss-bad.lua \
	t-verify-syntax t-verify-syntax.conf t-verify-syntax.lua \
	t-dontsign t-dontsign.conf t-dontsign.lua \
	t-peer t-peer.conf t-peer.list t-peer.lua \
	t-verify-report t-verify-report.conf t-verify-report.txt \
		t-verify-report.lua \
	t-adsp-report t-adsp-report.conf t-adsp-report.txt \
		t-adsp-report.lua \
	testkey.private pubkeys cp-test testmta


MOSTLYCLEANFILES=

if GCOV_ONLY
MOSTLYCLEANFILES+=*.gcov *.gcno *.gcda *.bb *.bbg *.da .gcov-files
#PROF_SRCS= opendkim.c opendkim.h opendkim-ar.c opendkim-ar.h opendkim-arf.c opendkim-arf.h opendkim-config.h opendkim-crypto.c opendkim-crypto.h opendkim-db.c opendkim-db.h opendkim-lua.c opendkim-lua.h config.c
#TESTS_ENVIRONMENT=./gcov-helper.sh

#.gcov-files: check-TESTS
#	for i in $(PROF_SRCS); do \
#		x=`echo $$i | sed 's/\..*//g'`; \
#		if test -f ../libopendkim_la-$$x.gcno -a \
#		        -f ../libopendkim_la-$$x.gcda; then \
#			mv ../libopendkim_la-$$x.gcno ../$$x.gcno; \
#			mv ../libopendkim_la-$$x.gcda ../$$x.gcda; \
#			gcov -o .. $$i; \
#		fi; \
#		if test -f ../libopendkim_la-$$x.bb -a \
#		        -f ../libopendkim_la-$$x.bbg -a \
#		        -f ../libopendkim_la-$$x.da; then \
#			mv ../libopendkim_la-$$x.bb ../$$x.bb; \
#			mv ../libopendkim_la-$$x.bbg ../$$x.bbg; \
#			mv ../libopendkim_la-$$x.da ../$$x.da; \
#			gcov -o .. $$i; \
#		fi; \
#	done
#	touch $@
#
#check-local: .gcov-files
endif

if LCOV
dist_doc_DATA=lcov
MAINTAINERCLEANFILES=description.txt description.html
MOSTLYCLEANFILES+=*.info .prepare-lcov .info-files *.gcno *.gcda
TESTS_ENVIRONMENT=./lcov-helper.sh

#.info-files: check-TESTS 
#	for i in $(TESTS); do \
#		lcov --capture --directory $(top_builddir) --output-file $$i.info \
#			--test-name $$i -q; \
#	done
#	touch .info-files

check-local: check-TESTS description.html
	genhtml --output-directory lcov *.info --show-details --highlight \
		--frames --legend  --title @PACKAGE@ \
		--description-file description.html

description.txt: $(check_SCRIPTS)
	rm -f $@
	for test in $? ; do \
		testname=$${test/t-}; \
		testname=$${testname//-/_}; \
		grep ^# $$test | tail -n 1 | \
			sed -e "s/^#\(.*\)/$${testname}\n\t\1\n/g" >> $@; \
	done
 
description.html: description.txt
	gendesc --output $@ $<

maintainer-clean-local:
	-rm -rf lcov/[^C]*

.PHONY: maintainer-clean-local check-local
endif

if GPROF
MOSTLYCLEANFILES+=*.prof gmon.out *.gmon

check-local: check-TESTS
	for i in $(check_PROGRAMS); do \
		./$$i; \
		gprof $$i > $$i.prof; \
	done
endif
