<?php
$conn = new mysqli("localhost", "root", "", "testdb");
$id = intval($_GET['id']);
$result = $conn->query("SELECT * FROM users WHERE id = " . $id);
?>