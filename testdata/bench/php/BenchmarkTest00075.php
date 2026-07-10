<?php
$file = $_GET['file'];
$safe = basename($file);
$path = "/uploads/" . $safe;
if (file_exists($path)) {
    readfile($path);
}
?>