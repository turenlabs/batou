<?php
// Hardcoded database credentials and secrets in source code.
// Vulnerable: credentials should come from environment variables or a vault.

// GTSS-SEC-001: Hardcoded password
$password = "S3cureP@ssw0rd!2024";

// GTSS-SEC-001: Hardcoded API key (fake value for testing)
$api_key = "aK9xMp2vL5nQ8wRtY3bG7dF1hJ0kS4u";

// Database credentials hardcoded directly
$db_host = "production-db.internal.company.com";
$db_user = "admin";
$db_password = "Pr0duct10n_DB_P@ss!";
$db_name = "main_app";

// GTSS-SEC-004: Connection string with credentials
$dsn = "mysql://admin:Pr0duct10n_DB_P@ss!@production-db.internal.company.com/main_app";

$conn = new mysqli($db_host, $db_user, $db_password, $db_name);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// GTSS-SEC-001: Hardcoded secret key
$secret = "my_jwt_signing_secret_key_2024";

// GTSS-SEC-005: JWT secret hardcoded
$jwt_secret = "xK9mP2vL5nQ8wRjT";

// Third-party API keys (test values matching known patterns)
$api_secret = "fK4mNp7qRs2tUv8xYz1aBcDeFgHiJkLmNoPqRs";

function getAuthToken() {
    $token = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    return $token;
}

function getDbConnection() {
    // GTSS-SEC-001: Hardcoded password in function
    $secret_key = "W8rn1ng_Th1s_1s_H@rdc0ded!";
    return new PDO(
        "mysql:host=prod.db.internal:3306;dbname=app",
        "root",
        $secret_key
    );
}
