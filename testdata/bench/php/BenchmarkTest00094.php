<?php
$url = $_GET['url'];
$parsed = parse_url($url);
if (!isset($parsed['host'])) { die("invalid"); }
$host = $parsed['host'];
$ip = gethostbyname($host);
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    echo file_get_contents($url);
}
?>