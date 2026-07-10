<?php
$pdo = new PDO("mysql:host=localhost;dbname=test", "root", "");
$email = $_POST['email'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
$stmt->execute([$email]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);
?>