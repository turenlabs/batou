<?php
// Safe: File upload with MIME type checking, size limit, and file renaming.
// Prevents upload of executable files.

$upload_dir = "uploads/";
$max_size = 2 * 1024 * 1024; // 2MB limit
$allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['userfile'])) {
    $file = $_FILES['userfile'];

    // Check for upload errors
    if ($file['error'] !== UPLOAD_ERR_OK) {
        die("Upload error: " . $file['error']);
    }

    // Check file size
    if ($file['size'] > $max_size) {
        die("File too large. Maximum size is 2MB.");
    }

    // Verify MIME type using finfo (not trusting user-supplied type)
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $actual_type = $finfo->file($file['tmp_name']);

    if (!in_array($actual_type, $allowed_types, true)) {
        die("Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed.");
    }

    // Verify extension
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($ext, $allowed_extensions, true)) {
        die("Invalid file extension.");
    }

    // Generate random filename to prevent overwrites and path traversal
    $new_name = bin2hex(random_bytes(16)) . '.' . $ext;
    $target_path = $upload_dir . $new_name;

    if (move_uploaded_file($file['tmp_name'], $target_path)) {
        echo "File uploaded successfully.";
    } else {
        echo "Upload failed.";
    }
}
?>

<!DOCTYPE html>
<html>
<body>
<h2>Upload an Image</h2>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="userfile" accept="image/*" />
    <input type="submit" value="Upload" />
</form>
</body>
</html>
