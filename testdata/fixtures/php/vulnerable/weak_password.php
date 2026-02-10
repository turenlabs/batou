<?php
// Weak password hashing using MD5/SHA1 without salt.
// Vulnerable: MD5 and SHA1 are cryptographically broken for passwords.

$conn = new mysqli("localhost", "app_user", getenv("DB_PASS"), "dvwa");

function registerUser($conn, $username, $password) {
    // GTSS-CRY-001: Weak hash - MD5 for password
    $hashed = md5($password);

    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->bind_param("ss", $username, $hashed);
    return $stmt->execute();
}

function loginUser($conn, $username, $password) {
    // GTSS-CRY-001: Weak hash - MD5 for password comparison
    $hashed = md5($password);

    $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? AND password = ?");
    $stmt->bind_param("ss", $username, $hashed);
    $stmt->execute();
    return $stmt->get_result()->num_rows > 0;
}

// SHA1 variant - also weak
function hashToken($token) {
    return sha1($token);
}

// Weak PRNG for token generation
function generateResetToken() {
    // GTSS-CRY-010: Weak PRNG for security token
    $token = md5(mt_rand());
    return $token;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'];
    $username = $_POST['username'];
    $password = $_POST['password'];

    if ($action === 'register') {
        registerUser($conn, $username, $password);
        echo "User registered.";
    } elseif ($action === 'login') {
        if (loginUser($conn, $username, $password)) {
            echo "Login successful.";
        } else {
            echo "Invalid credentials.";
        }
    }
}
