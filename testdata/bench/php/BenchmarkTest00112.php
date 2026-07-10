<?php
$cookie = $_COOKIE['prefs'];
$prefs = json_decode($cookie, true);
if (is_array($prefs)) {
    print_r($prefs);
}
?>