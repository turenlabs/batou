<?php
$pdo = new PDO("mysql:host=localhost;dbname=test", "root", "");
$search = $_GET['q'];
$stmt = $pdo->prepare("SELECT * FROM products WHERE name LIKE ?");
$stmt->execute(["%" . $search . "%"]);
?>