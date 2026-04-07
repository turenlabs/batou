<?php
// Remote File Inclusion (RFI).
// Vulnerable: include with remote URL if allow_url_include is enabled.

$page = $_GET['page'];

// GTSS-TRV-002: File inclusion with user-controlled path
// If allow_url_include is on, attacker can use http:// URLs
include($page);

// Another common RFI pattern with prefix
$theme = $_GET['theme'];
include("themes/" . $theme . "/header.php");

// Variant using require
$controller = $_REQUEST['controller'];
require($controller);

// Dynamic class loading (also dangerous)
$class_file = $_GET['class'];
require_once($class_file);
