<?php
$conn = mysqli_connect("localhost", "root", "", "testdb");
$name = $_POST['name'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $name . "'");
?>