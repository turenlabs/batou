<?php
$pdo = new PDO("mysql:host=localhost;dbname=test", "root", "");
$name = $_POST['name'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = :name");
$stmt->bindParam(':name', $name, PDO::PARAM_STR);
$stmt->execute();
?>