<?php
$conn = mysqli_connect("localhost", "root", "", "testdb");
$param = $_GET['id'];
$bar = $param;
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $bar);
?>