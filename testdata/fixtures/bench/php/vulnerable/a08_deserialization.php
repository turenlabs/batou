<?php
// Source: CWE-502 - Unsafe deserialization in PHP
// Expected: GTSS-GEN-002 (Unsafe Deserialization - unserialize)
// OWASP: A08:2021 - Software and Data Integrity Failures

function loadUserPrefs() {
    $cookie = $_COOKIE['prefs'];
    $decoded = base64_decode($cookie);
    $prefs = unserialize($decoded);
    return $prefs;
}

function importData() {
    $data = $_POST['import_data'];
    $objects = unserialize($data);
    foreach ($objects as $obj) {
        $obj->save();
    }
    echo 'Imported ' . count($objects) . ' records';
}

function restoreSession() {
    $sessionData = file_get_contents('php://input');
    $session = unserialize($sessionData);
    $_SESSION['user'] = $session['user'];
    $_SESSION['role'] = $session['role'];
    header('Location: /dashboard');
}
