<?php
$cookie = $_COOKIE['prefs'];
$prefs = unserialize($cookie);
print_r($prefs);
?>