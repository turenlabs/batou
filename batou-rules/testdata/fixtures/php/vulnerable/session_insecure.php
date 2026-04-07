<?php
// GTSS-PHP-007: Insecure session cookie configuration

// Vulnerable: httponly disabled
ini_set('session.cookie_httponly', 0);

// Vulnerable: secure disabled
ini_set('session.cookie_secure', false);

session_start();

// Store user data in session
$_SESSION['user_id'] = $user_id;
$_SESSION['role'] = $role;
