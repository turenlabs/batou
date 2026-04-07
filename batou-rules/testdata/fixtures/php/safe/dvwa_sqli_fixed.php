<?php
// DVWA SQL Injection - Fixed with prepared statements
$id = $_REQUEST['id'];

// SAFE: Using PDO prepared statements
$stmt = $pdo->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->execute([$id]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

if ($row) {
    $first = htmlspecialchars($row["first_name"], ENT_QUOTES, 'UTF-8');
    $last = htmlspecialchars($row["last_name"], ENT_QUOTES, 'UTF-8');
    echo "<pre>First name: {$first}<br />Surname: {$last}</pre>";
}
?>
