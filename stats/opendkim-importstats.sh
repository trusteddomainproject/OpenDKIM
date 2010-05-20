#!/bin/sh
##
## $Id: opendkim-importstats.sh,v 1.2 2010/05/20 18:39:10 cm-msk Exp $
##
## Copyright (c) 2010, The OpenDKIM Project.  All rights reserved.
##
## opendkim-importstats -- import opendkim-stats output to MySQL
##

## setup
database="opendkim"
user="opendkim"
password="opendkim"
statsdb="/var/db/opendkim/opendkim-stats.db"
anon="yes"

progname=`basename $0`

## Argument processing
while [ $# -gt 0 ]
do
	case $1 in
	-D)	anon="no"
		;;

	-d)	if [ $# -eq 1 ]
		then
			echo $progname: -d requires a value
			exit 1
		fi

		shift
		database=$1
		;;

	-p)	if [ $# -eq 1 ]
		then
			echo $progname: -p requires a value
			exit 1
		fi

		shift
		password=$1
		;;

	-s)	if [ $# -eq 1 ]
		then
			echo $progname: -s requires a value
			exit 1
		fi

		shift
		statsdb=$1
		;;

	*)	echo $progname: unknown flag $1
		exit 1
		;;
	esac

	shift
done

## capture data
if [ x"$anon" = x"no" ]
then
	anonstr=""
else
	anonstr="-a"
fi

if [ x"$statsdb" != x"" ]
then
	opendkim-stats $anonstr -c -r $statsdb > /tmp/opendkim-import.$$
else
	cat > /tmp/opendkim-import.$$
fi

## construct import command
import="load data infile '/tmp/opendkim-import.$$'
	into table opendkim_statistics
	lines starting by '='
	(
		jobid,
		from_domain,
		ipaddr,
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
