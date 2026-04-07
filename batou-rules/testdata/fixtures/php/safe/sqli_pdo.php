<?php
// Safe: SQL queries using PDO prepared statements with bound parameters.
// No SQL injection possible - user input is parameterized.

$dsn = "mysql:host=localhost;dbname=dvwa;charset=utf8mb4";
$username = getenv("DB_USER");
$password = getenv("DB_PASS");

$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
];

$pdo = new PDO($dsn, $username, $password, $options);

// Safe: parameterized SELECT
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT first_name, last_name FROM users WHERE user_id = :id");
$stmt->bindParam(':id', $id, PDO::PARAM_INT);
$stmt->execute();
$user = $stmt->fetch();

if ($user) {
    echo "Name: " . htmlspecialchars($user['first_name']) . " " . htmlspecialchars($user['last_name']);
}

// Safe: parameterized INSERT
$name = $_POST['name'];
$email = $_POST['email'];
$stmt = $pdo->prepare("INSERT INTO users (name, email) VALUES (:name, :email)");
$stmt->execute([':name' => $name, ':email' => $email]);

// Safe: parameterized search with LIKE
$search = $_GET['search'];
$stmt = $pdo->prepare("SELECT * FROM products WHERE name LIKE :search");
$stmt->execute([':search' => '%' . $search . '%']);
$results = $stmt->fetchAll();

// Safe: mysqli prepared statement
$conn = new mysqli("localhost", $username, $password, "dvwa");
$stmt = $conn->prepare("SELECT id, name FROM users WHERE email = ?");
$stmt->bind_param("s", $_POST['email']);
$stmt->execute();
$result = $stmt->get_result();
