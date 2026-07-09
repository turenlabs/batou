<?php
$conn = mysqli_connect("localhost", "root", "", "testdb");
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
?>
