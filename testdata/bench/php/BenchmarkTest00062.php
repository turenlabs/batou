<?php
$path = $_GET['path'];
$data = file_get_contents($path);
echo $data;
?>
