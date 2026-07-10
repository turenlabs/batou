<?php
$data = $_POST['data'];
$json = json_decode($data, true);
echo "<p>Hello, " . htmlspecialchars($json['name'] ?? '') . "</p>";
?>