<?php
$serialized = $_POST['config'];
$config = unserialize($serialized);
$config->apply();
?>