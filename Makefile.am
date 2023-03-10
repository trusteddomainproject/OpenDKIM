# Copyright (c) 2010-2014, The Trusted Domain Project.  All rights reserved.

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = 
SUBDIRS += libopendkim contrib docs
if VBR
SUBDIRS += libvbr
endif
if RBL
SUBDIRS += librbl
endif
if LUA
SUBDIRS += miltertest
endif
if STATS
SUBDIRS += stats
endif
if REPUTE
SUBDIRS += libut reputation
endif
if REPRRD
SUBDIRS += reprrd
endif
if JANSSON
SUBDIRS += autobuild
endif
SUBDIRS += opendkim
dist_doc_DATA = FEATURES KNOWNBUGS LICENSE LICENSE.Sendmail \
	RELEASE_NOTES.Sendmail
dist_noinst_SCRIPTS = libtool

DISTCLEANFILES = opendkim-@VERSION@.tar.gz

# TODO: get configure.ac to generate --enable-{feature} for all
# non-experimental features and substitute it here e.g  @SUPPORTED_FEATURES@.
# Perhaps all features would enable a more comprehensive test coverage map
# though.
DISTCHECK_CONFIGURE_FLAGS=--enable-vbr --with-lua --enable-stats --with-odbx --with-db --with-openssl=/usr/local --enable-atps --enable-replace_rules


#
# Handle some scripts and configuration files that need @VARIABLE@
# replacements here, so that we can share the rules (which are
# identical) between all of the targets.
#

# We want to *build and install* these on the target machine.
nodist_doc_DATA = contrib/OpenRC/opendkim.openrc \
                  contrib/systemd/opendkim.service \
                  contrib/systemd/opendkim.tmpfiles \
                  opendkim/opendkim.conf.simple \
                  opendkim/opendkim.conf.simple-verify

# Custom variable to keep the rule below as sane as possible.
doc_DATA_intermediate = contrib/OpenRC/opendkim.openrc.in

# We want to *ship* these.
EXTRA_DIST = contrib/OpenRC/opendkim.openrc.in.in \
             contrib/systemd/opendkim.service.in \
             contrib/systemd/opendkim.tmpfiles.in \
             opendkim/opendkim.conf.simple.in \
             opendkim/opendkim.conf.simple-verify.in

# The next rule allow us to replace bindir, libdir, etc.  within
# files. The example is taken from the autoconf documentation and can
# be found in the "Installation Directory Variables" section.
edit = sed -e 's|@DOMAIN[@]|$(DOMAIN)|g' \
           -e 's|@RUNSTATEDIR[@]|$(runstatedir)|g' \
           -e 's|@SBINDIR[@]|$(sbindir)|g' \
           -e 's|@SYSCONFDIR[@]|$(sysconfdir)|g'

# This rule includes EVERY source/intermediate file as a dependency of
# EVERY output file, which is clearly wrong, but it may be the best we
# can do without duplication. At least it's the right kind of wrong,
# and rebuilds too often rather than not often enough.
$(nodist_doc_DATA): $(doc_DATA_intermediate) $(EXTRA_DIST) Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in > $@.tmp
	mv $@.tmp $@




$(DIST_ARCHIVES): distcheck

$(DIST_ARCHIVES).md5: $(DIST_ARCHIVES)
	md5 $? > $@ || md5sum $? > $@

$(DIST_ARCHIVES).sha1: $(DIST_ARCHIVES)
	sha1 $? > $@ || sha1sum $? > $@

$(DIST_ARCHIVES).asc: $(DIST_ARCHIVES)
	gpg -a -u security@opendkim.org --detach-sign $?

push: $(DIST_ARCHIVES) $(DIST_ARCHIVES).sha1 $(DIST_ARCHIVES).md5 $(DIST_ARCHIVES).asc
	@echo "Are you sure you want to tag and release $(DIST_ARCHIVES)? (y/n)"
	@read confirm && [ $$confirm = 'y' ]
	git tag rel-opendkim-`echo $(VERSION) | sed 's/\./-/g'`
	git push --tags
	scp $(DIST_ARCHIVES) $(DIST_ARCHIVES).sha1 $(DIST_ARCHIVES).md5 $(DIST_ARCHIVES).asc RELEASE_NOTES cm-msk,opendkim@frs.sourceforge.net:/home/frs/project/o/op/opendkim/

dist-hook:
	[ -f $(distdir)/libopendkim/dkim.h ] && rm -f $(distdir)/libopendkim/dkim.h
	sed -e '/OPENDKIM_LIB_VERSION/s/0x[0-9]*/0x@HEX_VERSION@/' < $(srcdir)/libopendkim/dkim.h > $(distdir)/libopendkim/dkim.h
	echo "looking to see if @VERSION@ is in the RELEASE_NOTES"
	fgrep @VERSION@ $(srcdir)/RELEASE_NOTES
	sed -e 's|\(@VERSION@[ \t]*\)[0-9?]\{4\}\(/[0-9?]\{2\}\)\{2\}|\1'`date +%Y/%m/%d`'|' < $(srcdir)/RELEASE_NOTES > $(distdir)/RELEASE_NOTES

.PHONY: push
