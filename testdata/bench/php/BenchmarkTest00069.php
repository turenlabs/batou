<?php
$path = $_GET['page'];
$data = file_get_contents($path);
echo $data;
?>
