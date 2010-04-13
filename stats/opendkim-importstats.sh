#!/bin/sh
##
## $Id: opendkim-importstats.sh,v 1.1.2.1 2010/04/13 23:50:28 cm-msk Exp $
##
## Copyright (c) 2010, The OpenDKIM Project.  All rights reserved.
##
## opendkim-importstats -- import opendkim-stats output to MySQL
##

## setup
database="opendkim"
user="opendkim"
password="opendkim"
statsdb="/var/db/opendkim/stats.db"

## capture data
if [ x"$statsdb" != x"" ]
then
	opendkim-stats -c -r $statsdb > /tmp/opendkim-import.$$
else
	cat > /tmp/opendkim-import.$$
fi

## construct import command
import="load data infile '/tmp/opendkim-import.$$'
	into table opendkim_statistics
	lines starting by '='
	(
		jobid,
		@msgtime,
		algorithm,
		hdr_canon,
		body_canon,
		sigs_total,
		sigs_pass,
		sigs_fail,
		sigs_fail_body,
		extended,
		key_t,
		key_g,
		key_syntax,
		key_nx,
		sig_t,
		sig_t_future,
		sig_x,
		sig_l,
		sig_z,
		adsp,
		adsp_fail,
		adsp_discardable,
		author_sigs,
		author_sigs_fail,
		tp_sigs,
		tp_sigs_fail,
		mailing_list
	) set msgtime = from_unixtime(@msgtime);"

## import
mysql --user=$user --password=$password -e "$import" $database

## clean up
rm /tmp/opendkim-import.$$
exit 0
