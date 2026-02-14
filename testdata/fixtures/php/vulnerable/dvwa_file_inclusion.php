<?php
// DVWA File Inclusion (LFI/RFI)
// Expected: GTSS-PHP-003 (File Inclusion), GTSS-TRV-002
// CWE-98, CWE-22, OWASP A01

$page = $_GET['page'];

// VULNERABLE: DVWA Local File Inclusion
include($page);

// VULNERABLE: DVWA Remote File Inclusion
$file = $_REQUEST['file'];
include("pages/" . $file);

// VULNERABLE: require with user input
$template = $_GET['template'];
require($template . '.php');
?>
