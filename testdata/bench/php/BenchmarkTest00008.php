<?php
$conn = mysqli_connect("localhost", "root", "", "testdb");
$param = $_GET['sort'];
$sql = "SELECT * FROM users ORDER BY " . $param;
$result = mysqli_query($conn, $sql);
?>