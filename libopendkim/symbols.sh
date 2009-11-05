#!/bin/sh
#
# $Id: symbols.sh,v 1.1.2.1 2009/11/05 22:32:05 cm-msk Exp $
#
# Extract from dkim.h the list of symbols we want to export

SOURCEHDR=dkim.h
SYMLIST=symbols.map

grep '^extern' $SOURCEHDR | \
	awk '{ for (c = 1; c <= NF; c++) if ($c ~ /dkim_/) { print $c; break; } }' | \
	sed -e s/\[\*\;\]//g -e s/\[\\\[\\\]\]//g > $SYMLIST
