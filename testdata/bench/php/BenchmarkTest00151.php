<?php
$url = $_GET['url'];
$parsed = parse_url($url);
if (isset($parsed['host']) && $parsed['host'] === 'example.com') {
    header("Location: " . $url);
    exit;
}
header("Location: /");
?>