<?php
$input = $_POST['config'];
$config = yaml_parse($input);
print_r($config);
?>