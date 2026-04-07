<?php
// Safe: Command execution with escapeshellarg and allowlist validation.
// No command injection possible.

$allowed_hosts = ['google.com', 'github.com', 'example.com'];

if (isset($_POST['host'])) {
    $host = $_POST['host'];

    // Validate against allowlist
    if (!in_array($host, $allowed_hosts, true)) {
        die("Invalid host. Only approved hosts may be queried.");
    }

    // Safe: escapeshellarg prevents injection
    $safe_host = escapeshellarg($host);
    $output = shell_exec("ping -c 4 " . $safe_host);
    echo "<pre>" . htmlspecialchars($output, ENT_QUOTES, 'UTF-8') . "</pre>";
}

// Safe: using escapeshellcmd for the entire command
if (isset($_POST['domain'])) {
    $domain = $_POST['domain'];

    // Validate format
    if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/', $domain)) {
        die("Invalid domain format.");
    }

    $safe_domain = escapeshellarg($domain);
    $result = shell_exec("nslookup " . $safe_domain);
    echo "<pre>" . htmlspecialchars($result, ENT_QUOTES, 'UTF-8') . "</pre>";
}

// Safe: no shell at all - use PHP native functions instead
if (isset($_GET['ip'])) {
    $ip = $_GET['ip'];

    // Validate IP format
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        die("Invalid IP address.");
    }

    $hostname = gethostbyaddr($ip);
    echo "Hostname: " . htmlspecialchars($hostname, ENT_QUOTES, 'UTF-8');
}
