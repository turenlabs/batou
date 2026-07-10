<?php
$data = $_POST['data'];
$obj = json_decode($data, true);
echo $obj['name'];
?>