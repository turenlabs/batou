<?php
$conn = new mysqli("localhost", "root", "", "testdb");
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
$result = $conn->query("SELECT * FROM users WHERE id = " . $id);
?>