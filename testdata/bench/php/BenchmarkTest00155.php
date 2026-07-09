<?php
$url = $_GET['url'];
$parsed = parse_url($url);
$allowed_hosts = ['example.com', 'app.example.com'];
if (isset($parsed['host']) && in_array($parsed['host'], $allowed_hosts)) {
    header("Location: " . $url);
} else {
    header("Location: /");
}
?>