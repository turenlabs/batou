<?php
$file = $_GET['file'];
$base = "/uploads/";
$resolved = realpath($base . basename($file));
if ($resolved !== false && strpos($resolved, realpath($base)) === 0) {
    echo file_get_contents($resolved);
}
?>