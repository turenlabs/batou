<?php
$url = $_GET['return_url'];
header("Location: " . $url);
die();
?>