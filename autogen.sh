#!/bin/sh
#
# $Id: autogen.sh,v 1.2 2009/11/22 08:15:49 grooverdan Exp $
#

# Bail on script if any of the commands fail
set -e

# Pass --copy where appropriate to avoid symlinks
libtoolize --copy
autoheader
aclocal -I m4
autoconf
automake --add-missing --copy

