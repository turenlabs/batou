<?php
declare(strict_types=1);

define('UPLOAD_DIR', '/var/www/uploads');

// SAFE: realpath + str_starts_with for path traversal prevention
function downloadFile(string $fileName): void {
    $resolved = realpath(UPLOAD_DIR . '/' . $fileName);
    if ($resolved === false || !str_starts_with($resolved, UPLOAD_DIR)) {
        http_response_code(403);
        echo json_encode(['error' => 'Access denied']);
        return;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($resolved) . '"');
    readfile($resolved);
}

// SAFE: basename strips directory traversal components
function serveDocument(string $rawName): void {
    $safeName = basename($rawName);
    $path = UPLOAD_DIR . '/' . $safeName;

    if (!file_exists($path)) {
        http_response_code(404);
        echo json_encode(['error' => 'Not found']);
        return;
    }

    readfile($path);
}

// SAFE: Allowlist of permitted extensions
function uploadFile(array $file): array {
    $allowedExt = ['pdf', 'png', 'jpg', 'txt'];
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));

    if (!in_array($ext, $allowedExt, true)) {
        return ['error' => 'File type not allowed'];
    }

    $safeName = basename($file['name']);
    $dest = UPLOAD_DIR . '/' . $safeName;
    move_uploaded_file($file['tmp_name'], $dest);
    return ['saved' => $safeName];
}
