<?php
// DVWA-style insecure file upload.
// Vulnerable: no file type, extension, or size validation.

$upload_dir = "uploads/";

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['userfile'])) {
    $tmp_name = $_FILES['userfile']['tmp_name'];
    $name = $_FILES['userfile']['name'];

    // No validation at all - attacker can upload .php shell
    $target_path = $upload_dir . $name;

    if (move_uploaded_file($tmp_name, $target_path)) {
        echo "File uploaded successfully: <a href='$target_path'>$name</a>";
    } else {
        echo "Upload failed.";
    }
}
?>

<!DOCTYPE html>
<html>
<body>
<h2>Upload a File</h2>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="userfile" />
    <input type="submit" value="Upload" />
</form>
</body>
</html>
