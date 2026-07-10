<?php
$name = $_GET['name'];
$safe = basename($name);
echo file_get_contents("/uploads/" . $safe);
?>