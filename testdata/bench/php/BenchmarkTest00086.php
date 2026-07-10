<?php
$url = $_GET['url'];
$opts = ['http' => ['method' => 'GET']];
$ctx = stream_context_create($opts);
$data = file_get_contents($url, false, $ctx);
echo $data;
?>