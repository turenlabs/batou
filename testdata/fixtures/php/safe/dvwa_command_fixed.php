<?php
// DVWA Command Injection - Fixed with escapeshellarg
$target = $_REQUEST['ip'];

// SAFE: Using escapeshellarg to sanitize input
$sanitized = escapeshellarg($target);
$output = shell_exec('ping -c 4 ' . $sanitized);
echo "<pre>" . htmlspecialchars($output, ENT_QUOTES, 'UTF-8') . "</pre>";
?>
