<?php
$feed = $_COOKIE['feed_url'];
$xml = file_get_contents($feed);
echo $xml;
?>