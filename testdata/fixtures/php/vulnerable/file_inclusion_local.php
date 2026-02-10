<?php
// DVWA-style local file inclusion (LFI).
// Vulnerable: user-controlled path passed directly to include/require.

$page = $_GET['page'];

// GTSS-TRV-002: Dynamic file inclusion with variable
include($page);

// Variant with string concatenation
$module = $_GET['module'];
require("modules/" . $module . ".php");

// require_once variant
$lang = $_REQUEST['lang'];
include_once($lang);

// Common but still vulnerable: extension appended
$template = $_GET['template'];
require_once("templates/" . $template);
