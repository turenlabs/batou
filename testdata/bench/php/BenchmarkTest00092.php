<?php
$url = $_GET['url'];
$parsed = parse_url($url);
$allowed = ['api.example.com', 'cdn.example.com'];
if (isset($parsed['host']) && in_array($parsed['host'], $allowed)) {
    echo file_get_contents($url);
}
?>