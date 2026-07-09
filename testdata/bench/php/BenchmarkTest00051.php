<?php
$dir = $_GET['dir'];
$safe = escapeshellarg($dir);
exec("ls " . $safe);
?>