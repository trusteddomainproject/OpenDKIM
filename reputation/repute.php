<?php
###
### Copyright (c) 2011, The OpenDKIM Project.  All rights reserved.
###

#
# PHP code to query a reputation datbaase and generate a reputon
#

#
# load local configuration for databae values
#
require "repute-config.php";

#
# extract query values and build the SQL query
#
$application = $_GET["application"];
$assertion = $_GET["assertion"];
$service = $_GET["service"];
$subject = $_GET["subject"];

if (!isset($subject) || !isset($application) || !isset($assertion) ||
    !isset($service))
	die("Malformed query");
if (strtolower($application) != "email")
	die("Unrecognized application");
if (strtolower($assertion) != "sends-spam")
	die("Unrecognized assertion");

$query = "SELECT ratio_high, UNIX_TIMESTAMP(updated), rate_samples
          FROM predictions
          WHERE name = '$subject'";

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
# run the query
#
if (!($result = mysql_query($query, $connection)))
	die("Query failed");

#
# extract results
#
$row = mysql_fetch_array($result, MYSQL_NUM);
$rating = $row[0];
$updated = $row[1];
$samples = $row[2];

#
# construct the reputon
#
printf("<reputation>\n");
printf(" <reputon>\n");
printf("  <rater>$service</rater>\n");
printf("  <rater-authenticity>1</rater-authenticity>\n");
printf("  <assertion>sends-spam</assertion>\n");
printf("  <extension>IDENTITY: DKIM</extension>\n");
printf("  <rated>$subject</rated>\n");
printf("  <rating>$rating</rating>\n");
printf("  <sample-size>$samples</sample-size>\n");
printf("  <updated>$updated</updated>\n");
printf(" </reputon>\n");
printf("</reputation>\n");

# all done!
?>
