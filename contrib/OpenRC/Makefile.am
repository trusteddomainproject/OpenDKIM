# We want to *build and install* this one on the target machine.
nodist_doc_DATA = opendkim.openrc

# Custom variable to keep the rule below as sane as possible.
doc_DATA_intermediate = opendkim.openrc.in

# But we want to *ship* this one...
EXTRA_DIST = opendkim.openrc.in.in


# The next rule allow us to replace bindir, libdir, etc.  within our
# service script. The example is taken from the autoconf documentation
# and can be found in the "Installation Directory Variables" section.
edit = sed -e 's|@RUNSTATEDIR[@]|$(runstatedir)|g' \
           -e 's|@SBINDIR[@]|$(sbindir)|g' \
           -e 's|@SYSCONFDIR[@]|$(sysconfdir)|g'

# This rule includes EVERY intermediate file as a dependency of EVERY
# output file, which is clearly wrong, but it may be the best we can
# do without duplication. At least it's the right kind of wrong, and
# rebuilds too often rather than not often enough.
$(nodist_doc_DATA): $(doc_DATA_intermediate) Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in > $@.tmp
	mv $@.tmp $@
