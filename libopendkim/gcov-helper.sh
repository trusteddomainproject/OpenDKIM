#!/bin/sh
$1
myname=`basename $1`
mv *$myname.gcda $myname.gcda
mv *$myname.gcno $myname.gcno
