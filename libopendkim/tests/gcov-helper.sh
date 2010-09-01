#!/bin/sh
./$1
x=$?
myname=`basename $1`
if test x"$OSTYPE" = x"OpenBSD"
then
	mv *$myname.bb $myname.bb
	mv *$myname.bbg $myname.bbg
	mv *$myname.da $myname.da
else
	mv *$myname.gcda $myname.gcda
	mv *$myname.gcno $myname.gcno
fi
exit $x
