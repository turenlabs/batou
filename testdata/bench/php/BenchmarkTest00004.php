<?php
$conn = new mysqli("localhost", "root", "", "testdb");
$val = $_REQUEST['search'];
$sql = "SELECT * FROM products WHERE name LIKE '%" . $val . "%'";
$result = mysqli_query($conn, $sql);
?>