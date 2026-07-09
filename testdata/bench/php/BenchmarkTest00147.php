<?php
$dest = $_COOKIE['redirect'];
header("Location: " . $dest);
exit;
?>