<?php
$path = $_GET['path'];
$safe = urlencode($path);
$url = "https://api.example.com/" . $safe;
echo file_get_contents($url);
?>