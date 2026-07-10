<?php
$param = $_COOKIE['logfile'];
$content = file_get_contents($param);
echo $content;
?>
