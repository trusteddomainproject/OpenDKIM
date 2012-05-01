<?php
###
### Copyright (c) 2011, 2012, The OpenDKIM Project.  All rights reserved.
###

#
# PHP code to query a reputation database and generate a reputon
#

#
# load local configuration for databae values
#
require "repute-config.php";

#
# extract query values and build the SQL query
#
if (!isset($_GET["application"]) ||
    !isset($_GET["assertion"]) ||
    !isset($_GET["service"]) ||
    !isset($_GET["subject"]))
	die("Malformed query");

$application = $_GET["application"];
$assertion = $_GET["assertion"];
$service = $_GET["service"];
$subject = $_GET["subject"];

if (strtolower($application) != "email-id")
	die("Unrecognized application");
if (strtolower($assertion) != "spam")
	die("Unrecognized assertion");

if (isset($_GET["reporter"]))
	$reporter = $_GET["reporter"];
else
	$reporter = 0;

if (isset($_GET["format"]))
{
	$format = $_GET["format"];
	if (strtolower($format) != "xml" &&
	    strtolower($format) != "json")
		die("Unrecognized format");
	else if (strtolower($format) == "xml")
		$use_json = 0;
	else
		$use_json = 1;
}

$query1 = "SELECT	ratio_high,
			UNIX_TIMESTAMP(updated),
			rate_samples
           FROM		predictions
           WHERE	name = '$subject'
           AND          reporter = 0";
 
$query2 = "SELECT	daily_limit_low
           FROM		predictions
           WHERE	name = '$subject'
           AND          reporter = $reporter";
 
#
# connect to the DB
#
if (!($connection = mysql_connect($repute_db, $repute_user, $repute_pwd)))
	die("Unable to connect to database server");

# 
# select the DB
# 
if (!mysql_select_db($repute_dbname, $connection))
	die("Unable to connect to database");

#
# run the first query
#
if (!($result = mysql_query($query1, $connection)))
	die("Query failed");

#
# extract results
#
$row = mysql_fetch_array($result, MYSQL_NUM);
if (!$row)
	die("No data available");
$rating = $row[0];
$updated = $row[1];
$samples = $row[2];

#
# run the second query
#
if (!($result = mysql_query($query2, $connection)))
	die("Query failed");

$row = mysql_fetch_array($result, MYSQL_NUM);
if (!$row)
	die("No data available");
$rate = $row[0];

#
# MIME header
#

printf("Content-Type: application/reputon\n");
printf("\n");

#
# Construct the reputon
#

if (isset($use_json) && $use_json == 1)
{
	printf("{\n");
	printf("\t\"rater\": \"$service\",\n");
	printf("\t\"rater-authenticity\": 1.0,\n");
	printf("\t\"assertion\": \"SPAM\",\n");
	printf("\t\"identity\": \"DKIM\",\n");
	printf("\t\"rate\": $rate\n");
	printf("\t\"rated\": \"$subject\",\n");
	printf("\t\"rating\": $rating,\n");
	printf("\t\"sample-size\": $samples,\n");
	printf("\t\"updated\": $updated\n");
	printf("}\n");
}
else
{
	printf("<reputation>\n");
	printf(" <reputon>\n");
	printf("  <rater>$service</rater>\n");
	printf("  <rater-authenticity>1</rater-authenticity>\n");
	printf("  <assertion>SPAM</assertion>\n");
	printf("  <identity>DKIM</identity>\n");
	printf("  <rate>$rate</rate>\n");
	printf("  <rated>$subject</rated>\n");
	printf("  <rating>$rating</rating>\n");
	printf("  <sample-size>$samples</sample-size>\n");
	printf("  <updated>$updated</updated>\n");
	printf(" </reputon>\n");
	printf("</reputation>\n");
}

# all done!
?>
