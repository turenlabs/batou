<?php
// DVWA Weak Session IDs
// Expected: GTSS-PHP-007 (Insecure Session Cookie), GTSS-AUTH-006
// CWE-330, OWASP A07

// VULNERABLE: DVWA weak session ID - predictable session using timestamp
$html = "";
if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $cookie_value = time();
    setcookie("dvwaSession", $cookie_value);
}

// VULNERABLE: Session without secure flags
session_start();
$_SESSION['user'] = $_POST['username'];
$_SESSION['admin'] = false;

// VULNERABLE: no httponly, no secure flags on session cookie
ini_set('session.cookie_httponly', 0);
ini_set('session.cookie_secure', 0);
?>
