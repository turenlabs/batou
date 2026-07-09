<?php
$data = $_POST['data'];
$allowed = ['StdClass', 'UserPrefs'];
$obj = unserialize($data, ['allowed_classes' => $allowed]);
?>