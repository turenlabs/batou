<?php
// Missing CSRF protection on state-changing form.
// Vulnerable: no CSRF token validation on POST requests.

session_start();
$conn = new mysqli("localhost", "app_user", getenv("DB_PASS"), "dvwa");

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // No CSRF token check - any site can submit this form
    $new_password = $_POST['password'];
    $confirm = $_POST['confirm_password'];
    $user_id = $_SESSION['user_id'];

    if ($new_password === $confirm) {
        $hashed = password_hash($new_password, PASSWORD_BCRYPT);
        $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
        $stmt->bind_param("si", $hashed, $user_id);
        $stmt->execute();
        echo "Password changed successfully.";
    } else {
        echo "Passwords do not match.";
    }
}
?>

<!DOCTYPE html>
<html>
<body>
<h2>Change Password</h2>
<!-- No CSRF token in form -->
<form method="POST" action="">
    <label>New Password:</label>
    <input type="password" name="password" required /><br/>
    <label>Confirm Password:</label>
    <input type="password" name="confirm_password" required /><br/>
    <input type="submit" value="Change Password" />
</form>
</body>
</html>
