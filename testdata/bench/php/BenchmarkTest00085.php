<?php
$endpoint = $_GET['endpoint'];
$bar = $endpoint;
$response = file_get_contents($bar);
echo $response;
?>