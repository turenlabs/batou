<?php
$msg = $_GET['msg'];
echo htmlentities($msg, ENT_QUOTES, 'UTF-8');
?>