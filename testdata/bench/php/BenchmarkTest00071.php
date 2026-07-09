<?php
$file = $_GET['file'];
$base = realpath("/uploads/");
$path = realpath("/uploads/" . $file);
if ($path !== false && strpos($path, $base) === 0) {
    echo file_get_contents($path);
}
?>