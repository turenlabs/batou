<?php
// Safe: URL allowlist validation before making outbound requests.
// Expected: No findings for BATOU-SSRF-001

$allowed_hosts = ['api.example.com', 'cdn.example.com', 'service.internal'];

if (isset($_GET['url'])) {
    $target = $_GET['url'];
    $parsed = parse_url($target);

    // Validate host against allowlist
    if (!isset($parsed['host']) || !in_array($parsed['host'], $allowed_hosts, true)) {
        http_response_code(403);
        die("Host not allowed");
    }

    // Validate scheme
    if (!in_array($parsed['scheme'] ?? '', ['http', 'https'], true)) {
        http_response_code(400);
        die("Invalid scheme");
    }

    // Safe: only allowlisted hosts are fetched
    $ch = curl_init($target);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    $result = curl_exec($ch);
    curl_close($ch);

    echo htmlspecialchars($result, ENT_QUOTES, 'UTF-8');
}

// Safe: hardcoded base URL with user-controlled path
if (isset($_GET['endpoint'])) {
    $endpoint = $_GET['endpoint'];
    $base = 'https://api.example.com';

    // Validate path format
    if (strpos($endpoint, '..') !== false || $endpoint[0] !== '/') {
        http_response_code(400);
        die("Invalid endpoint");
    }

    $url = $base . $endpoint;
    $response = file_get_contents($url);
    echo htmlspecialchars($response, ENT_QUOTES, 'UTF-8');
}
