<?php
$conn = mysqli_connect("localhost", "root", "", "testdb");
$token = $_COOKIE['session_token'];
$result = mysqli_query($conn, "SELECT * FROM sessions WHERE token = '" . $token . "'");
?>