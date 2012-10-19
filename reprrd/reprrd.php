<?php
###
### Copyright (c) 2011, 2012, The Trusted Domain Project.  All rights reserved.
###

##
## PHP code to query for an RRD that shows flow data for a given domain
##

#
# load local configuration
#

require "reprrd-config.php";

if (isset($timezone))
	date_default_timezone_set($timezone);
else
	date_default_timezone_set('UTC');

#
# extract and validate query values (i.e., domain name)
#

if (!isset($_GET["domain"]) ||
    !isset($_GET["type"]))
	die("Malformed query (missing parameter)");

$domain = strtolower($_GET["domain"]);
$type = strtolower($_GET["type"]);

if ($type != "messages" && $type != "spam")
	die("Malformed query (invalid type)");

if (preg_match('/[a-z0-9.-]/', $domain) != 1 || strlen($domain) > 255)
	die("Malformed query (domain syntax)");

#
# see if there's data available for the selected domain
# 

$dompath = "";

for ($n = 0; $n < $rrddepth; $n++)
{
	$dompath = $dompath . "/" . substr($domain, $n, 1);
}

$dompath = $dompath . "/" . $domain;

$rrdpath = $rrdroot . "/" . $type . $dompath;

if (!file_exists($rrdpath))
	die("No " . $type . " data for " . $domain . " at " . $rrdpath);

$test = fopen($rrdpath, "r");
if (!$test)
	die("Can't read from " . $rrdpath);
fclose($test);

#
# generate graphs
#

$tmpdir = $rrdroot . "/tmp";

$tmppath = $tmpdir . "/" . $domain . "-" . $type . "-" . getmypid();

$test = fopen($tmppath, "w");
if (!$test)
	die("Can't write to " . $tmppath);
fclose($test);

$options = array (
	"--imgformat=PNG",
	"--title=" . $domain . " " . $type . " at " . date("D, d M Y H:i:s"),
	"--start=-1209600",
	"--height=480",
	"--width=1500",
	"--alt-autoscale-max",
	"--lower-limit=0",
	"--vertical-label=Messages/Hour",
	"--slope-mode",
	"--font", "TITLE:8:",
	"--font", "AXIS:8:",
	"--font", "LEGEND:10:",
	"--font", "UNIT:8:",
	"DEF:a=" . $rrdpath . ":" . $type . ":AVERAGE",
	"DEF:b=" . $rrdpath . ":" . $type . ":HWPREDICT",
	"DEF:c=" . $rrdpath . ":" . $type . ":DEVPREDICT",
	"DEF:d=" . $rrdpath . ":" . $type . ":FAILURES",
	"CDEF:upper=b,c,2,*,+",
	"TICK:d#ccbb00:1.0:Failures",
	"LINE2:a#ff0000:Message Rate",
	"LINE1:upper#0000ff:Upper Bounds"
);

printf("DEF:a=" . $rrdpath . ":messages:AVERAGE\n");
$out = rrd_graph($tmppath, $options);
if (!$out)
	die("Failed to create graph at " . $tmppath);

#
# load graph for inline presentation
#

$in = fopen($tmppath, "r");
if (!$in)
	die("Can't open " . $tmppath);
$imgraw = fread($in, filesize($tmppath));
fclose($in);
$imgdata = base64_encode($imgraw);
unlink($tmppath);

#
# output page
# 

printf("Content-Type: text/html\n");
printf("\n");
printf("<html>\n");
printf(" <head>\n");
printf("  <title>Recent " . $type . " history for " . $domain . "</title>\n");
printf(" </head>\n");
printf(" <body bgcolor=\"#000000\">\n");
printf("  <img src=\"data:image/png;base64," . $imgdata . "\" alt=\"" . $domain . " " . $type . " data\">\n");
printf(" </body>\n");
printf("</html>\n");

# all done!
?>
