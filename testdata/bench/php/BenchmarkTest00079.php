<?php
$id = intval($_GET['id']);
$path = "/uploads/" . $id . ".pdf";
readfile($path);
?>