<?php
$host = $_GET['host'];
$safe = escapeshellcmd($host);
system("ping -c 4 " . $safe);
?>