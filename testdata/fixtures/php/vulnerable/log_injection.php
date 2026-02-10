<?php
// Log injection via unsanitized user input in logging functions.
// Vulnerable: user input can inject newlines to forge log entries.

$username = $_POST['username'];
$action = $_GET['action'];

// GTSS-LOG-001: User input in error_log without sanitization
error_log("User login attempt: " . $username . " from " . $_SERVER['REMOTE_ADDR']);

// GTSS-LOG-001: User input in syslog
syslog(LOG_INFO, "Action performed: " . $action . " by user " . $username);

// GTSS-LOG-003: Logging sensitive data - password in log
$password = $_POST['password'];
error_log("Login attempt with password: " . $password);

// Laravel-style logging with user input
// Log::info("User search: " . $_GET['query']);

// CRLF injection: user can inject newlines to forge log entries
$search_term = $_GET['q'];
error_log("[SEARCH] User searched for: " . $search_term);

// Sensitive data logged
$api_key = $_POST['api_key'];
error_log("API request with api_key: " . $api_key);

// Combined: user input + sensitive data in syslog
$token = $_COOKIE['auth_token'];
syslog(LOG_WARNING, "Token validation for token: " . $token . " user: " . $_GET['user']);
