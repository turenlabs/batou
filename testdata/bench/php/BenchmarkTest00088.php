<?php
$img_url = $_GET['img'];
$img = file_get_contents($img_url);
header("Content-Type: image/png");
echo $img;
?>