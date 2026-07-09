<?php
$conn = new mysqli("localhost", "root", "", "testdb");
$name = $conn->real_escape_string($_GET['name']);
$result = $conn->query("SELECT * FROM users WHERE name = '" . $name . "'");
?>