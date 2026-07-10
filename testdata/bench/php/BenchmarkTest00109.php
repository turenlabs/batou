<?php
$param = $_GET['state'];
$state = unserialize($param);
if ($state->isAdmin) { echo "admin"; }
?>