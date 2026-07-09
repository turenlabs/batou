<?php
$raw = $_REQUEST['obj'];
$bar = $raw;
$object = unserialize($bar);
echo $object->value;
?>