<?php
$conn = mysqli_connect("localhost", "root", "", "testdb");
$input = $_GET['q'];
$term = $input;
$query = "SELECT * FROM items WHERE description LIKE '%" . $term . "%'";
$result = mysqli_query($conn, $query);
?>