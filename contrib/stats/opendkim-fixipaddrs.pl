#!/usr/bin/perl
#
# Copyright (c) 2011, The Trusted Domain Project.  All rights reserved.
#
# Script to clean out duplicate entries in the "ipaddrs" table, and update
# the "messages" table accordingly.

###
### Setup
###

use strict;
use warnings;

use DBI;
use File::Basename;
use Getopt::Long;
use IO::Handle;
use POSIX;

require DBD::mysql;

# general
my $progname      = basename($0);
my $version       = "\@VERSION@";
my $verbose       = 0;
my $helponly      = 0;

my $maxid;
my $dup;
my $idx;
my $addr;
my $nrows;

my $dbi_s;
my $dbi_s_getaddr;
my $dbi_s_getdup;
my $dbi_s_repair;
my $dbi_s_cleanup;
my $dbi_h;
my $dbi_a;

my $thresh;

# DB parameters
my $def_dbhost    = "localhost";
my $def_dbname    = "opendkim";
my $def_dbuser    = "opendkim";
my $def_dbpasswd  = "opendkim";
my $def_dbport    = "3306";
my $dbhost;
my $dbname;
my $dbuser;
my $dbpasswd;
my $dbport;

my $dbscheme     = "mysql";

###
### NO user-serviceable parts beyond this point
###

sub usage
{
	print STDERR "$progname: usage: $progname [options]\n";
	print STDERR "\t--dbhost=host      DB host [$def_dbhost]\n";
	print STDERR "\t--dbname=name      DB name [$def_dbname]\n";
	print STDERR "\t--dbpasswd=pwd     DB password [$def_dbpasswd]\n";
	print STDERR "\t--dbport=port      DB port [$def_dbport]\n";
	print STDERR "\t--dbuser=user      DB user [$def_dbuser]\n";
	print STDERR "\t--help             print help and exit\n";
	print STDERR "\t--verbose          verbose output\n";
}

# parse command line arguments
my $opt_retval = &Getopt::Long::GetOptions ('dbhost=s' => \$dbhost,
                                            'dbname=s' => \$dbname,
                                            'dbpasswd=s' => \$dbpasswd,
                                            'dbport=s' => \$dbport,
                                            'dbuser=s' => \$dbuser,
                                            'help!' => \$helponly,
                                            'verbose!' => \$verbose,
                                           );

if (!$opt_retval || $helponly)
{
	usage();

	if ($helponly)
	{
		exit(0);
	}
	else
	{
		exit(1);
	}
}

# apply defaults
if (!defined($dbhost))
{
	if (defined($ENV{'OPENDKIM_DBHOST'}))
	{
		$dbhost = $ENV{'OPENDKIM_DBHOST'};
	}
	else
	{
		$dbhost = $def_dbhost;
	}
}

if (!defined($dbname))
{
	if (defined($ENV{'OPENDKIM_DB'}))
	{
		$dbname = $ENV{'OPENDKIM_DB'};
	}
	else
	{
		$dbname = $def_dbname;
	}
}

if (!defined($dbpasswd))
{
	if (defined($ENV{'OPENDKIM_PASSWORD'}))
	{
		$dbpasswd = $ENV{'OPENDKIM_PASSWORD'};
	}
	else
	{
		$dbpasswd = $def_dbpasswd;
	}
}

if (!defined($dbport))
{
	if (defined($ENV{'OPENDKIM_PORT'}))
	{
		$dbport = $ENV{'OPENDKIM_PORT'};
	}
	else
	{
		$dbport = $def_dbport;
	}
}

if (!defined($dbuser))
{
	if (defined($ENV{'OPENDKIM_USER'}))
	{
		$dbuser = $ENV{'OPENDKIM_USER'};
	}
	else
	{
		$dbuser = $def_dbuser;
	}
}

my $dbi_dsn = "DBI:" . $dbscheme . ":database=" . $dbname .
              ";host=" . $dbhost . ";port=" . $dbport;

$dbi_h = DBI->connect($dbi_dsn, $dbuser, $dbpasswd, { PrintError => 0 });
if (!defined($dbi_h))
{
	print STDERR "$progname: unable to connect to database: $DBI::errstr\n";
	exit(1);
}

if ($verbose)
{
	print STDERR "$progname: connected to database\n";
}

# get the highest ID
$dbi_s = $dbi_h->prepare("SELECT MAX(id) FROM ipaddrs");
if (!$dbi_s->execute)
{
	print STDERR "$progname: can't get maximum ID\n";
	$dbi_s->finish;
	$dbi_h->disconnect;
	exit(1);
}
else
{
	$dbi_a = $dbi_s->fetchrow_arrayref();
	if (defined($dbi_a->[0]))
	{
		$maxid = $dbi_a->[0];
	}
	else
	{
		print STDERR "$progname: can't get maximum ID\n";
		$dbi_s->finish;
		$dbi_h->disconnect;
		exit(1);
	}
}

if ($verbose)
{
	print STDERR "$progname: maximum ID is $maxid\n";
}

$dbi_s->finish;

$dbi_s_getaddr = $dbi_h->prepare("SELECT addr FROM ipaddrs
                                  WHERE id = ?");
$dbi_s_getdup  = $dbi_h->prepare("SELECT id   FROM ipaddrs
                                  WHERE addr = ? AND id > ?");
$dbi_s_repair  = $dbi_h->prepare("UPDATE messages SET ip = ?
                                  WHERE ip = ?");
$dbi_s_cleanup = $dbi_h->prepare("DELETE FROM ipaddrs
                                  WHERE id = ?");

for ($idx = 1; $idx < $maxid; $idx++)
{
	$dbi_s_getaddr->execute($idx);
	$dbi_a = $dbi_s_getaddr->fetchrow_arrayref();
	if (defined($dbi_a->[0]))
	{
		$addr = $dbi_a->[0];
	}
	else
	{
		print STDERR "$progname: skipping id $idx\n";
		$dbi_s_getaddr->finish;
		next;
	}
	$dbi_s_getaddr->finish;

	$dbi_s_getdup->execute($addr, $idx);
	$dbi_a = $dbi_s_getdup->fetchrow_arrayref();
	if (defined($dbi_a->[0]))
	{
		$dup = $dbi_a->[0];
		if ($verbose)
		{
			print STDERR "$progname: id $idx duplicate $dup found\n";
		}
	}
	else
	{
		$dbi_s_getdup->finish;
		next;
	}
	$dbi_s_getdup->finish;

	$nrows = $dbi_s_repair->execute($idx, $dup);
	if ($nrows == -1)
	{
		print STDERR "$progname: error updating messages table for id $idx\n";
		$dbi_s_repair->finish;
		next;
	}
	elsif ($verbose)
	{
		print STDERR "$progname: $nrows row(s) updated\n";
	}

	$dbi_s_repair->finish;

	if ($dbi_s_cleanup->execute($dup) == -1)
	{
		print STDERR "$progname: error cleaning ipaddrs table for id $dup\n";
		$dbi_s_cleanup->finish;
		next;
	}
	elsif ($verbose)
	{
		print STDERR "$progname: id $dup removed from ipaddrs\n";
	}

	$dbi_s_cleanup->finish;
}

# all done!
if ($verbose)
{
	print STDERR "$progname: done\n";
}

$dbi_h->disconnect;

exit(0);
