<?php
$page = intval($_GET['page']);
$url = "https://api.example.com/articles?page=" . $page;
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
echo curl_exec($ch);
?>