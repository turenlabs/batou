<?php
// Source: OWASP DVWA - Reflected XSS
// Expected: BATOU-XSS-010 (Reflected XSS via echo of user input)
// OWASP: A03:2021 - Injection (Reflected XSS)

function displaySearch() {
    $query = $_GET['q'];
    echo "<html><body>";
    echo "<h1>Search Results</h1>";
    echo "<p>You searched for: " . $query . "</p>";
    echo "<form method='GET'><input name='q' value='" . $query . "'></form>";
    echo "</body></html>";
}

function displayProfile($pdo) {
    $userId = $_GET['id'];
    $stmt = $pdo->query("SELECT * FROM users WHERE id = $userId");
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    echo "<h1>Profile: " . $user['name'] . "</h1>";
    echo "<div class='bio'>" . $user['bio'] . "</div>";
}

function displayError() {
    $message = $_GET['error'];
    echo "<div class='alert alert-danger'>$message</div>";
}
