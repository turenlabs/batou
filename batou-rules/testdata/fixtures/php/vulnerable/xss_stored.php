<?php
// Stored XSS: user input saved to DB then displayed without escaping.

$conn = new mysqli("localhost", "app_user", getenv("DB_PASS"), "dvwa");

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $comment = $_POST['comment'];
    $author = $_POST['author'];

    // Store without sanitization
    $stmt = $conn->prepare("INSERT INTO comments (author, body) VALUES (?, ?)");
    $stmt->bind_param("ss", $author, $comment);
    $stmt->execute();
    $stmt->close();
}

// Display stored comments without escaping
$result = $conn->query("SELECT author, body, created_at FROM comments ORDER BY created_at DESC");

echo "<h2>Comments</h2>";
while ($row = $result->fetch_assoc()) {
    // GTSS-XSS-004: echo with variable, no htmlspecialchars
    echo "<div class='comment'>";
    echo "<strong>" . $row['author'] . "</strong>";
    echo "<p>" . $row['body'] . "</p>";
    echo "<small>" . $row['created_at'] . "</small>";
    echo "</div>";
}

// Also vulnerable: direct echo of user-controlled variable
<?php echo $row['body']; ?>

$conn->close();
