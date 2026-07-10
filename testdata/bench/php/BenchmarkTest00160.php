<?php
$url = $_GET['url'];
$base = "https://example.com";
$parsed = parse_url($url);
if (isset($parsed['path']) && !isset($parsed['host'])) {
    header("Location: " . $base . $parsed['path']);
    exit;
}
header("Location: " . $base);
?>