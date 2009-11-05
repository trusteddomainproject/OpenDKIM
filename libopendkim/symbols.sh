#!/bin/sh
#
# $Id: symbols.sh,v 1.1.2.2 2009/11/05 22:54:46 cm-msk Exp $
#
# Extract from dkim.h the list of symbols we want to export

SOURCEHDRS="dkim.h dkim-test.h"
SYMLIST=symbols.map

pwd
grep '^extern' $SOURCEHDRS | \
	awk '{ for (c = 1; c <= NF; c++) if ($c ~ /dkim_/) { print $c; break; } }' | \
	sed -e s/\[\*\;\]//g -e s/\[\\\[\\\]\]//g > $SYMLIST
