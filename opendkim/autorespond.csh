#!/bin/csh -f
##
##
## Copyright (c) 2004, 2005 Sendmail, Inc. and its suppliers.
## All rights reserved.
##
## Copyright (c) 2009, 2012, The Trusted Domain Project.  All rights reserved.
##
## autorespond.csh -- accept a message and reply to it to test signing and
## verifying of opendkim

## Setup
set infile=/var/tmp/ari.$$
set tmpfile=/var/tmp/aro.$$
set hostname=`hostname`

## Capture the incoming message
cat > $infile

## Build the reply
echo From: autorespond@$hostname >> $tmpfile
grep '^From:' < $infile | sed 's/^From/To/g' >> $tmpfile
## Enable the next line to allow remote canonicalization selection:
# grep '^X-Canonicalization:' < $infile >> $tmpfile
echo Subject: Auto-response from $hostname >> $tmpfile
echo "" >> $tmpfile
echo "Original message:" >> $tmpfile
echo "" >> $tmpfile
cat $infile >> $tmpfile
echo "" >> $tmpfile
echo "And some random data:" >> $tmpfile
echo "" >> $tmpfile
dd if=/dev/urandom count=10 | base64 -e >> $tmpfile

## Send the reply
sendmail -t < $tmpfile

## Clean up
rm -f $tmpfile $infile

exit 0
