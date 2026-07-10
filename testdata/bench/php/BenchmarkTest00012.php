<?php
$pdo = new PDO("mysql:host=localhost;dbname=test", "root", "");
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $id]);
$result = $stmt->fetchAll();
?>