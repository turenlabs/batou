<?php
// Safe: All user output properly escaped with htmlspecialchars.
// No XSS possible - all dynamic content is HTML-encoded.

$name = $_GET['name'] ?? '';
$search = $_GET['search'] ?? '';
?>
<!DOCTYPE html>
<html>
<head>
    <title>Greeting Page</title>
    <meta charset="UTF-8">
</head>
<body>

<h1>Hello, <?php echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8'); ?></h1>

<form method="GET" action="">
    <label for="name">Enter your name:</label>
    <input type="text" id="name" name="name" value="<?php echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8'); ?>" />
    <input type="submit" value="Submit" />
</form>

<?php if ($search): ?>
    <p>Search results for: <?php echo htmlspecialchars($search, ENT_QUOTES, 'UTF-8'); ?></p>
<?php endif; ?>

<?php
// Safe: displaying database content with escaping
$conn = new mysqli("localhost", getenv("DB_USER"), getenv("DB_PASS"), "dvwa");
$result = $conn->query("SELECT author, body FROM comments ORDER BY created_at DESC");

while ($row = $result->fetch_assoc()) {
    echo "<div class='comment'>";
    echo "<strong>" . htmlspecialchars($row['author'], ENT_QUOTES, 'UTF-8') . "</strong>";
    echo "<p>" . htmlspecialchars($row['body'], ENT_QUOTES, 'UTF-8') . "</p>";
    echo "</div>";
}

// Safe: using strip_tags for plain text extraction
$bio = strip_tags($_POST['bio'] ?? '');
echo "<p>" . htmlspecialchars($bio, ENT_QUOTES, 'UTF-8') . "</p>";
?>

</body>
</html>
