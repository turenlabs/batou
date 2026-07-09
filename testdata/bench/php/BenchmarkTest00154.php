<?php
$url = $_GET['url'];
if (strpos($url, '/') === 0 && strpos($url, '//') !== 0) {
    header("Location: " . $url);
    exit;
}
header("Location: /");
?>