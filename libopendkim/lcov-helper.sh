#!/bin/sh
lcov --zerocounters --directory .  -q
$1
lcov --capture --directory . --output-file $1.info --test-name ${1:4}  -q

