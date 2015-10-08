check_SCRIPTS = t-sign-ss t-sign-rs t-sign-rs-tables t-sign-rs-tables-bad \
	t-sign-rs-tables-token t-sign-rs-multiple t-sign-rs-mixconf \
	t-sign-rs-lua t-sign-ss-all t-sign-ss-ltag t-sign-ss-x \
	t-verify-revoked t-verify-unspec t-verify-malformed \
	t-verify-unsigned t-verify-unsigned-silent \
	t-verify-syntax t-verify-ss t-verify-ss-bad t-verify-ss-ar-bad \
	t-dontsign t-peer \
	t-lua-verify-tests t-sign-ss-macro t-sign-ss-macro-value \
	t-sign-ss-macro-value-file t-verify-report \
	t-sign-report t-conf-check t-verify-double-from

if LIVE_TESTS
if RBL
check_SCRIPTS += t-lua-rbl
endif
endif
if REPUTE
check_SCRIPTS += t-verify-ss-rep
endif
if REPLACE_RULES
check_SCRIPTS += t-sign-ss-replace
endif
if ATPS
check_SCRIPTS += t-sign-atps t-verify-ss-atps
endif
if CONDITIONAL
check_SCRIPTS += t-sign-ss-conditional
endif
if TEST_SOCKET
TESTS_ENVIRONMENT = MILTERTESTFLAGS=-DTESTSOCKET=$(TESTSOCKET); export MILTERTESTFLAGS;
endif

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
	t-sign-ss-x t-sign-ss-x.conf t-sign-ss-x.lua \
	t-sign-ss-all t-sign-ss-all.conf t-sign-ss-all.lua \
	t-sign-ss-ltag t-sign-ss-ltag.conf t-sign-ss-ltag.lua \
	t-sign-ss-macro t-sign-ss-macro.conf t-sign-ss-macro.lua \
	t-sign-ss-macro-value t-sign-ss-macro-value.conf \
		t-sign-ss-macro-value.lua \
	t-sign-ss-macro-value-file t-sign-ss-macro-value-file.conf \
		t-sign-ss-macro-value-file.lua \
		t-sign-ss-macro-value-file.list \
	t-sign-ss-replace t-sign-ss-replace.conf t-sign-ss-replace.lua \
		t-sign-ss-replace.txt \
	t-sign-report t-sign-report.conf t-sign-report.lua \
	t-sign-ss-conditional t-sign-ss-conditional.conf \
		t-sign-ss-conditional.lua \
	t-verify-revoked t-verify-revoked.conf t-verify-revoked.lua \
	t-verify-unsigned t-verify-unsigned.conf t-verify-unsigned.lua \
	t-verify-malformed t-verify-malformed.conf t-verify-malformed.lua \
	t-verify-unsigned-silent t-verify-unsigned-silent.conf \
		t-verify-unsigned-silent.lua \
	t-verify-unspec t-verify-unspec.conf t-verify-unspec.lua \
	t-verify-ss t-verify-ss.conf t-verify-ss.lua \
	t-verify-ss-bad t-verify-ss-bad.conf t-verify-ss-bad.lua \
	t-verify-ss-ar-bad t-verify-ss-ar-bad.conf t-verify-ss-ar-bad.lua \
	t-verify-ss-rep t-verify-ss-rep.conf t-verify-ss-rep.lua \
	t-verify-syntax t-verify-syntax.conf t-verify-syntax.lua \
	t-verify-double-from t-verify-double-from.conf \
		t-verify-double-from.lua \
	t-dontsign t-dontsign.conf t-dontsign.lua \
	t-lua-rbl t-lua-rbl.conf t-lua-rbl.lua t-lua-rbl.lua-final \
	t-lua-verify-tests t-lua-verify-tests.lua t-lua-verify-tests.conf \
		t-lua-verify-tests.lua-setup \
	t-peer t-peer.conf t-peer.list t-peer.lua \
	t-verify-report t-verify-report.conf t-verify-report.txt \
		t-verify-report.lua \
	t-sign-atps t-sign-atps.conf t-sign-atps.lua \
	t-verify-ss-atps t-verify-ss-atps.conf t-verify-ss-atps.lua \
	t-conf-check t-conf-check.conf t-conf-check.keytable t-conf-check.lua \
		t-conf-check.signtable t-conf-check2.conf \
		t-conf-check2.keytable t-conf-check2.lua \
		t-conf-check2.signtable t-largecomment.conf \
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
