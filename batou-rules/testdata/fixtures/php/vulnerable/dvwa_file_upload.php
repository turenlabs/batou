<?php
// DVWA File Upload
// Expected: GTSS-TRV-001 (Path Traversal)
// CWE-434, OWASP A04

$target_path = "uploads/";
$target_path .= basename($_FILES['uploaded']['name']);

// VULNERABLE: DVWA file upload - no validation of file type or content
if (move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)) {
    echo "<pre>{$target_path} successfully uploaded!</pre>";
} else {
    echo "<pre>Your image was not uploaded.</pre>";
}
?>
