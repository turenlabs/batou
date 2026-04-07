<?php
// DVWA SQL Injection
// Expected: GTSS-INJ-001 (SQL Injection), GTSS-PHP-006
// CWE-89, OWASP A03

$id = $_REQUEST['id'];

// VULNERABLE: DVWA SQL injection - string concat in query
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);

while ($row = mysqli_fetch_assoc($result)) {
    $first = $row["first_name"];
    $last = $row["last_name"];
    echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
}

// VULNERABLE: DVWA blind SQL injection
$cookie_id = $_COOKIE['id'];
$query2 = "SELECT 1 FROM users WHERE user_id = '$cookie_id' LIMIT 1;";
$result2 = mysqli_query($GLOBALS["___mysqli_ston"], $query2);
?>
