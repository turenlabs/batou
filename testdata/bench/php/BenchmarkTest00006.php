<?php
$conn = mysqli_connect("localhost", "root", "", "testdb");
$name = $_GET['name'];
$sql = "SELECT * FROM users WHERE name = '" . $name . "'";
$result = mysqli_query($conn, $sql);
?>