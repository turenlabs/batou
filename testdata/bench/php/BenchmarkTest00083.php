<?php
$url = $_GET['target'];
$data = file_get_contents($url);
echo $data;
?>
