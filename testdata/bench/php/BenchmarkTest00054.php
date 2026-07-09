<?php
$file = $_GET['file'];
$allowed = ['report.txt', 'data.csv', 'log.txt'];
if (in_array($file, $allowed)) {
    exec("cat " . escapeshellarg($file));
}
?>