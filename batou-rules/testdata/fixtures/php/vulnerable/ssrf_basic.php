<?php
// Server-Side Request Forgery (SSRF) via user-controlled URL.
// Vulnerable: user can provide any URL to fetch resources from internal network.

if (isset($_GET['url'])) {
    $url = $_GET['url'];

    // GTSS: SSRF via file_get_contents with user URL
    $content = file_get_contents($url);

    if ($content !== false) {
        echo "<h2>Page Preview</h2>";
        echo $content;
    } else {
        echo "Failed to fetch URL.";
    }
}

// SSRF via cURL
if (isset($_POST['webhook_url'])) {
    $webhook_url = $_POST['webhook_url'];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $webhook_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    echo "Webhook response ($http_code): " . htmlspecialchars($response);
}

// Image proxy - common SSRF vector
if (isset($_GET['image_url'])) {
    $image_url = $_GET['image_url'];
    header("Content-Type: image/png");
    readfile($image_url);
}
