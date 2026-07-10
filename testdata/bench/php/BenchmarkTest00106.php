<?php
$data = file_get_contents("php://input");
$obj = unserialize($data);
process($obj);
?>