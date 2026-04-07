<?php
// Safe: Password hashing with password_hash (bcrypt) and password_verify.
// Uses PHP's built-in secure functions.

$pdo = new PDO(
    "mysql:host=localhost;dbname=dvwa;charset=utf8mb4",
    getenv("DB_USER"),
    getenv("DB_PASS"),
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
);

function registerUser(PDO $pdo, string $username, string $password): bool {
    // Safe: password_hash with PASSWORD_BCRYPT includes automatic salt
    $hashed = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

    $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (:user, :pass)");
    return $stmt->execute([':user' => $username, ':pass' => $hashed]);
}

function loginUser(PDO $pdo, string $username, string $password): bool {
    $stmt = $pdo->prepare("SELECT password FROM users WHERE username = :user");
    $stmt->execute([':user' => $username]);
    $row = $stmt->fetch();

    if (!$row) {
        // Constant-time comparison even when user not found
        password_verify($password, '$2y$12$dummyhashtopreventtimingleak000000000000000000000');
        return false;
    }

    // Safe: password_verify handles timing-safe comparison
    return password_verify($password, $row['password']);
}

function generateResetToken(): string {
    // Safe: cryptographically secure random token
    return bin2hex(random_bytes(32));
}

function generateCsrfToken(): string {
    // Safe: random_bytes is CSPRNG
    return base64_encode(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if (strlen($password) < 8) {
        echo "Password must be at least 8 characters.";
    } else {
        registerUser($pdo, $username, $password);
        echo "User registered securely.";
    }
}
