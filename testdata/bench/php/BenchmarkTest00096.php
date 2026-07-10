<?php
$url = $_GET['url'];
$parsed = parse_url($url);
if (isset($parsed['scheme']) && $parsed['scheme'] === 'https' && isset($parsed['host']) && $parsed['host'] === 'api.trusted.com') {
    echo file_get_contents($url);
}
?>