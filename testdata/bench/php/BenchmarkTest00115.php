<?php
$config = unserialize(file_get_contents("/etc/app/config.ser"));
$config->apply();
?>