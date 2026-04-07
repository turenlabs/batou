<?php
// Source: OWASP Damn Vulnerable Web Application (DVWA) - SQL Injection
// Expected: BATOU-INJ-001 (SQL Injection via string concatenation)
// OWASP: A03:2021 - Injection (SQL Injection)

function searchProducts($pdo, $searchTerm) {
    $sql = "SELECT * FROM products WHERE name LIKE '%" . $searchTerm . "%'";
    $stmt = $pdo->query($sql);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function getUserById($pdo, $id) {
    $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    $result = mysqli_query($pdo, $query);
    return mysqli_fetch_assoc($result);
}

function login($pdo) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $pdo->query($sql);
    if ($result->rowCount() > 0) {
        $_SESSION['user'] = $result->fetch(PDO::FETCH_ASSOC);
        header('Location: /dashboard');
    } else {
        echo "Invalid credentials";
    }
}
