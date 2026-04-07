<?php
// Safe: CSRF protection with token generation and validation.
// Prevents cross-site request forgery.

session_start();

function generateCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken(string $token): bool {
    if (empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

$pdo = new PDO(
    "mysql:host=localhost;dbname=dvwa;charset=utf8mb4",
    getenv("DB_USER"),
    getenv("DB_PASS"),
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
);

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token before processing
    $submitted_token = $_POST['csrf_token'] ?? '';

    if (!validateCsrfToken($submitted_token)) {
        http_response_code(403);
        die("CSRF token validation failed. Request rejected.");
    }

    // Regenerate token after successful validation (single-use tokens)
    unset($_SESSION['csrf_token']);

    $new_password = $_POST['password'] ?? '';
    $confirm = $_POST['confirm_password'] ?? '';
    $user_id = $_SESSION['user_id'] ?? 0;

    if (strlen($new_password) < 8) {
        $message = "Password must be at least 8 characters.";
    } elseif ($new_password !== $confirm) {
        $message = "Passwords do not match.";
    } else {
        $hashed = password_hash($new_password, PASSWORD_BCRYPT, ['cost' => 12]);
        $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
        $stmt->execute([$hashed, $user_id]);
        $message = "Password changed successfully.";
    }
}

$csrf_token = generateCsrfToken();
?>
<!DOCTYPE html>
<html>
<body>
<h2>Change Password</h2>

<?php if ($message): ?>
    <p><?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></p>
<?php endif; ?>

<form method="POST" action="">
    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>" />
    <label>New Password:</label>
    <input type="password" name="password" required minlength="8" /><br/>
    <label>Confirm Password:</label>
    <input type="password" name="confirm_password" required minlength="8" /><br/>
    <input type="submit" value="Change Password" />
</form>
</body>
</html>
