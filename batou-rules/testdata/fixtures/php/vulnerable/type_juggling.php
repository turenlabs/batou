<?php
// GTSS-PHP-001: Type juggling vulnerability
// Uses loose comparison on security-sensitive values

function authenticate($username, $password) {
    $stored_hash = get_password_hash($username);
    // Vulnerable: loose comparison allows type juggling
    // "0e123" == "0e456" evaluates to true (both treated as 0)
    if ($password == $stored_hash) {
        return true;
    }
    return false;
}

function verify_token($token) {
    $expected = get_csrf_token();
    // Vulnerable: loose comparison
    if ($token != $expected) {
        die("CSRF token mismatch");
    }
}

function check_otp($user_otp, $stored_otp) {
    // Vulnerable: loose comparison on OTP
    if ($user_otp == $stored_otp) {
        grant_access();
    }
}
