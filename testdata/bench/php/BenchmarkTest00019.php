<?php
$conn = new mysqli("localhost", "root", "", "testdb");
$id = (int) $_GET['id'];
$result = $conn->query("SELECT * FROM users WHERE id = " . $id);
?>