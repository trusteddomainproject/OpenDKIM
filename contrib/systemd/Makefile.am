# Copyright (c) 2013, The Trusted Domain Project.  All rights reserved.

#
# TODO: install these for real and not as documentation.
#

# We want to *build and install* these...
nodist_doc_DATA = opendkim.service opendkim.tmpfiles

# but *ship* these.
EXTRA_DIST = opendkim.service.in opendkim.tmpfiles.in

# The next rule allow us to replace bindir, libdir, etc.  within our
# service file. The example is taken from the autoconf documentation
# and can be found in the "Installation Directory Variables" section.
edit = sed -e 's|@RUNSTATEDIR[@]|$(runstatedir)|g' \
           -e 's|@SBINDIR[@]|$(sbindir)|g' \
           -e 's|@SYSCONFDIR[@]|$(sysconfdir)|g'

# This rule includes EVERY source file as a dependency of EVERY
# output file, which is clearly wrong, but it may be the best we can
# do without duplication. At least it's the right kind of wrong, and
# rebuilds too often rather than not often enough.
$(nodist_doc_DATA): $(EXTRA_DIST) Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in > $@.tmp
	mv $@.tmp $@
