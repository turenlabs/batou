<?php
// DVWA-style SQL injection via string concatenation in mysqli_query.
// Vulnerable: user input is interpolated directly into the SQL query.

$servername = "localhost";
$username = "app_user";
$dbpass = getenv("DB_PASS");
$dbname = "dvwa";

$conn = new mysqli($servername, $username, $dbpass, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$id = $_GET['id'];

// GTSS-INJ-001: SQL injection via variable interpolation
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
$result = mysqli_query($conn, $query);

if ($result) {
    while ($row = $result->fetch_assoc()) {
        echo "Name: " . $row['first_name'] . " " . $row['last_name'] . "<br>";
    }
} else {
    echo "Query failed: " . mysqli_error($conn);
}

// Also vulnerable: concatenation style
$name = $_POST['name'];
$query2 = "SELECT * FROM users WHERE username = '" . $name . "'";
$result2 = $conn->query($query2);

$conn->close();
