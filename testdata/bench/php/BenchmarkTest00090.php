<?php
$webhook = $_POST['webhook'];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $webhook);
curl_setopt($ch, CURLOPT_POST, true);
curl_exec($ch);
?>