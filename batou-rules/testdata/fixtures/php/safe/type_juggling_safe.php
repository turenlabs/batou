<?php
// Safe: strict comparison and hash_equals

function authenticate($username, $password) {
    $stored_hash = get_password_hash($username);
    // Safe: strict comparison
    if ($password === $stored_hash) {
        return true;
    }
    return false;
}

function verify_token($token) {
    $expected = get_csrf_token();
    // Safe: hash_equals for timing-safe comparison
    if (!hash_equals($expected, $token)) {
        die("CSRF token mismatch");
    }
}
