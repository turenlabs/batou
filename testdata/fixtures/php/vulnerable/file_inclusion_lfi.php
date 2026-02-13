<?php
// GTSS-PHP-003: Local/Remote File Inclusion

// Vulnerable: include with user-controlled path
$page = $_GET['page'];
include($page);

// Vulnerable: require_once with concatenation
$template = $_POST['template'];
require_once("templates/" . $template);

// Vulnerable: include_once with dynamic variable
$module = $_REQUEST['module'];
include_once($module);
