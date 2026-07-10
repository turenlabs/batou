<?php
$msg = $_GET['msg'];
$safe = htmlspecialchars($msg, ENT_QUOTES, 'UTF-8');
$html = "<div class='alert'>{$safe}</div>";
echo $html;
?>