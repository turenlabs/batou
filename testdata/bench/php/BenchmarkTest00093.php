<?php
$ch = curl_init("https://api.internal.example.com/status");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$result = curl_exec($ch);
echo $result;
?>