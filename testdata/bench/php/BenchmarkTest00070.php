<?php
$file = $_POST['filename'];
$data = file_get_contents($file);
echo $data;
?>
