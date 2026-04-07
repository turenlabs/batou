<?php
// GTSS-PHP-002: SSRF via file_get_contents and curl

function fetch_url($url) {
    // Vulnerable: user-controlled URL
    $content = file_get_contents($url);
    return $content;
}

function proxy_request() {
    $target = $_GET['url'];
    // Vulnerable: SSRF via fopen
    $handle = fopen($target, 'r');
    $data = fread($handle, 8192);
    fclose($handle);
    echo $data;
}

function curl_fetch($userUrl) {
    $ch = curl_init();
    // Vulnerable: user-controlled CURLOPT_URL
    curl_setopt($ch, CURLOPT_URL, $userUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}
