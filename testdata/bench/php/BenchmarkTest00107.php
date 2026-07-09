<?php
$session = $_COOKIE['session_data'];
$user = unserialize($session);
echo "Welcome " . $user->name;
?>