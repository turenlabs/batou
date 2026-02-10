<?php
// DVWA-style command injection via system/shell_exec/exec.
// Vulnerable: user input passed directly to shell functions.

if (isset($_POST['ip'])) {
    $target = $_POST['ip'];

    // GTSS-INJ-002: Command injection via system()
    system("ping -c 4 " . $target);
}

if (isset($_GET['host'])) {
    $host = $_GET['host'];

    // GTSS-INJ-002: Command injection via shell_exec()
    $output = shell_exec("nslookup " . $host);
    echo "<pre>$output</pre>";
}

if (isset($_GET['file'])) {
    $filename = $_GET['file'];

    // GTSS-INJ-002: Command injection via exec()
    exec("cat /var/log/" . $filename, $lines);
    foreach ($lines as $line) {
        echo htmlspecialchars($line) . "<br>";
    }
}

// Backtick variant
if (isset($_POST['domain'])) {
    $domain = $_POST['domain'];
    // GTSS-INJ-002: Command injection via passthru()
    passthru("whois " . $domain);
}

// popen variant
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    $handle = popen($cmd, "r");
    echo fread($handle, 4096);
    pclose($handle);
}
