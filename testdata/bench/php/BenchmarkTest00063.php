<?php
$file = $_POST['file'];
$data = file_get_contents($file);
echo $data;
?>
