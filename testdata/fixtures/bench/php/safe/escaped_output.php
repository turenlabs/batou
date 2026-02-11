<?php
declare(strict_types=1);

// SAFE: htmlspecialchars for output escaping
function renderSearchPage(string $query): string {
    $safeQuery = htmlspecialchars($query, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    return '<div class="results"><p>Results for: ' . $safeQuery . '</p></div>';
}

// SAFE: htmlspecialchars on all user-controlled values
function renderUserProfile(array $user): string {
    $name = htmlspecialchars($user['name'], ENT_QUOTES, 'UTF-8');
    $bio = htmlspecialchars($user['bio'], ENT_QUOTES, 'UTF-8');
    return "<h1>{$name}</h1><p>{$bio}</p>";
}

// SAFE: JSON response with proper content type
function jsonResponse(array $data): void {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP);
}

// SAFE: strip_tags for plain text extraction
function plainTextExcerpt(string $html, int $length = 200): string {
    $text = strip_tags($html);
    if (strlen($text) > $length) {
        $text = substr($text, 0, $length) . '...';
    }
    return $text;
}
