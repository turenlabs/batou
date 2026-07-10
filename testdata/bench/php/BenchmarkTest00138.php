<?php
$title = $_GET['title'];
$safe_title = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
$template = "<html><head><title>%s</title></head></html>";
echo sprintf($template, $safe_title);
?>