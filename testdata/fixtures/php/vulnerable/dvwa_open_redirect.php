<?php
// DVWA Open Redirect
// Expected: GTSS-GEN-004 (Open Redirect), GTSS-REDIR-001
// CWE-601, OWASP A01

$redirect_url = $_GET['redirect'];

// VULNERABLE: DVWA open redirect - redirecting to user-controlled URL
header("Location: " . $redirect_url);
exit;
?>
