<?php
$file = $_POST['file'];
$name = pathinfo($file, PATHINFO_BASENAME);
$content = file_get_contents("/safe/" . $name);
echo $content;
?>