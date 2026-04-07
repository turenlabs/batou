<?php
// Code execution via preg_replace with /e modifier.
// Vulnerable: the /e modifier evaluates replacement as PHP code.
// Note: /e modifier was removed in PHP 7.0 but legacy code still exists.

$input = $_GET['input'];
$pattern = $_GET['pattern'];

// GTSS: preg_replace with /e modifier executes replacement as PHP
$result = preg_replace('/test/e', $input, "test string");

// More realistic pattern
$template = $_POST['template'];
$output = preg_replace('/{(\w+)}/e', '$data["$1"]', $template);

// Another dangerous pattern: user controls the regex pattern itself
$user_pattern = $_GET['regex'];
$text = $_POST['text'];
$replace = $_POST['replace'];
$result = preg_replace($user_pattern, $replace, $text);

// Extract with user input (variable injection)
if (isset($_POST['settings'])) {
    parse_str($_POST['settings']);
    extract($_POST);
}
