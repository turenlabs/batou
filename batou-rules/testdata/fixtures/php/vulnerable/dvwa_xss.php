<?php
// DVWA XSS (Reflected, Stored, DOM)
// Expected: GTSS-XSS-011 (Reflected XSS)
// CWE-79, OWASP A03

// VULNERABLE: DVWA reflected XSS - echoing user input directly
$name = $_GET['name'];
echo '<pre>Hello ' . $name . '</pre>';

// VULNERABLE: DVWA stored XSS - output from DB without escaping
$message = $_POST['mtxMessage'];
$name2 = $_POST['txtName'];
$query = "INSERT INTO guestbook (comment, name) VALUES ('$message', '$name2')";
mysqli_query($GLOBALS["___mysqli_ston"], $query);
echo "<pre>Comment saved: {$message} by {$name2}</pre>";

// VULNERABLE: DVWA DOM XSS - passing user input to client
$lang = $_GET['default'];
echo "<script>document.write('" . $lang . "')</script>";
?>
