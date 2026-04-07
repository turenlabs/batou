<?php
// Path traversal via file_get_contents with user-controlled path.
// Vulnerable: no sanitization of ../ sequences in file path.

$filename = $_GET['file'];

// GTSS-TRV-001: file_get_contents with user input
$content = file_get_contents($filename);

if ($content !== false) {
    echo "<pre>" . htmlspecialchars($content) . "</pre>";
} else {
    echo "File not found.";
}

// Variant: readfile with user path
$doc = $_GET['doc'];
readfile("documents/" . $doc);

// Variant: fopen with user path
$path = $_POST['path'];
$fp = fopen($path, "r");
if ($fp) {
    echo fread($fp, filesize($path));
    fclose($fp);
}

// Variant: file_put_contents path traversal for writes
$logfile = $_GET['logfile'];
file_put_contents("logs/" . $logfile, date("Y-m-d H:i:s") . " - accessed\n", FILE_APPEND);
