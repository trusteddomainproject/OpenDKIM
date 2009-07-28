#!/bin/sh
#
# $Id: autogen.sh,v 1.1 2009/07/28 22:19:30 mmarkley Exp $
#

# Bail on script if any of the commands fail
set -e

# Pass --copy where appropriate to avoid symlinks
libtoolize --copy
autoheader
aclocal
autoconf
automake --add-missing --copy

