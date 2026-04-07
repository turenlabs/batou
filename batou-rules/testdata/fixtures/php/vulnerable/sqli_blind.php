<?php
// Blind SQL injection with boolean-based detection.
// Vulnerable: user input flows into SQL query with no sanitization.

$conn = new mysqli("localhost", "app_user", getenv("DB_PASS"), "dvwa");

if ($conn->connect_error) {
    die("Connection failed");
}

$id = $_GET['id'];

// GTSS-INJ-001: Blind boolean-based SQL injection
$query = "SELECT 1 FROM users WHERE user_id = '$id' LIMIT 1";
$result = mysqli_query($conn, $query);

if ($result && $result->num_rows > 0) {
    echo '<p>User exists.</p>';
} else {
    echo '<p>User not found.</p>';
}

// Blind time-based variant
$search = $_GET['search'];
$query2 = "SELECT * FROM products WHERE name LIKE '%$search%'";
$result2 = $conn->query($query2);

if ($result2) {
    echo "<p>Found " . $result2->num_rows . " results.</p>";
}

$conn->close();
