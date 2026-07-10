<?php
$file = $_GET['file'];
$fp = fopen($file, "r");
echo fread($fp, 4096);
fclose($fp);
?>
