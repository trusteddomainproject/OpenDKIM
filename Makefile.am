# $Id: Makefile.am,v 1.55 2010/07/21 21:28:36 cm-msk Exp $

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = 
if USE_ARLIB
SUBDIRS += libar
endif
SUBDIRS += libopendkim contrib docs
if VBR
SUBDIRS += libvbr
endif
if LUA
SUBDIRS += miltertest
endif
if STATS
SUBDIRS += stats
endif
SUBDIRS += opendkim
dist_doc_DATA = FEATURES KNOWNBUGS LICENSE LICENSE.Sendmail \
	RELEASE_NOTES.Sendmail

DISTCLEANFILES = opendkim-@VERSION@.tar.gz

# TODO: get configure.ac to generate --enable-{feature} for all
# non-experimental features and substitute it here e.g  @SUPPORTED_FEATURES@.
# Perhaps all features would enable a more comprehensive test coverage map
# though.
DISTCHECK_CONFIGURE_FLAGS=--enable-arlib --enable-vbr --with-lua

dist-hook:
	[ -f $(distdir)/libopendkim/dkim.h ] && rm -f $(distdir)/libopendkim/dkim.h
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
