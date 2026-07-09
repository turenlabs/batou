<?php
$conn = new mysqli("localhost", "root", "", "testdb");
$result = $conn->query("SELECT * FROM users WHERE active = 1");
?>