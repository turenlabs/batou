<?php
// Safe: File includes use a strict allowlist. File reads validate with realpath.
// No path traversal or file inclusion possible.

// Safe file inclusion: strict allowlist
$allowed_pages = [
    'home' => 'pages/home.php',
    'about' => 'pages/about.php',
    'contact' => 'pages/contact.php',
    'faq' => 'pages/faq.php',
];

$page = $_GET['page'] ?? 'home';

if (array_key_exists($page, $allowed_pages)) {
    include($allowed_pages[$page]);
} else {
    include('pages/404.php');
}

// Safe file read: realpath validation + base directory check
$base_dir = realpath(__DIR__ . '/documents');
$requested_file = $_GET['file'] ?? '';

$full_path = realpath($base_dir . '/' . basename($requested_file));

if ($full_path !== false && strpos($full_path, $base_dir) === 0) {
    $content = file_get_contents($full_path);
    echo "<pre>" . htmlspecialchars($content, ENT_QUOTES, 'UTF-8') . "</pre>";
} else {
    echo "File not found or access denied.";
}

// Safe: template includes with allowlisted extensions
$template = $_GET['template'] ?? 'default';
$safe_template = preg_replace('/[^a-zA-Z0-9_-]/', '', $template);
$template_path = "templates/" . $safe_template . ".phtml";

if (file_exists($template_path)) {
    include($template_path);
}
