<?php
$url = $_POST['url'];
$parsed = parse_url($url);
$allowlist = ['example.com', 'trusted.org'];
if (isset($parsed['host']) && in_array($parsed['host'], $allowlist)) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    echo curl_exec($ch);
}
?>