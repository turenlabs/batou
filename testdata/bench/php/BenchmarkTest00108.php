<?php
$encoded = $_POST['encoded'];
$decoded = base64_decode($encoded);
$obj = unserialize($decoded);
?>