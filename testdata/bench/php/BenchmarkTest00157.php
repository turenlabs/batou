<?php
$path = $_GET['path'];
$safe = "/" . ltrim(parse_url($path, PHP_URL_PATH), "/");
header("Location: " . $safe);
exit;
?>