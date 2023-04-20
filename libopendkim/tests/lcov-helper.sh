#!/bin/bash
$1
x=$?
# keep consistent with Makefile.am
testname=${1/.\/t-}
testname=${testname//-/_}
lcov --capture --directory .. --output-file $1.info --test-name ${testname} --quiet
lcov --remove $1.info '/usr/include/*' --output-file $1.info --quiet &
exit $x
