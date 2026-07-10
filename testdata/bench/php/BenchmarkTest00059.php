<?php
$file = $_POST['file'];
$safe = basename($file);
exec("wc -l " . escapeshellarg($safe));
?>