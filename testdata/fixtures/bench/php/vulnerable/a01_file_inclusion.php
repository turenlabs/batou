<?php
// Source: OWASP DVWA - File Inclusion
// Expected: GTSS-TRV-002 (File Inclusion via include/require with user input)
// OWASP: A01:2021 - Broken Access Control (Local/Remote File Inclusion)

function loadPage() {
    $page = $_GET['page'];
    include("pages/" . $page);
}

function loadTemplate() {
    $template = $_GET['template'];
    $lang = $_GET['lang'] ?? 'en';
    require_once("templates/$lang/" . $template . ".php");
}

function loadModule() {
    $module = $_POST['module'];
    $path = "/var/www/modules/" . $module;
    if (file_exists($path)) {
        include($path);
    } else {
        echo "Module not found";
    }
}

function readLogFile() {
    $logFile = $_GET['log'];
    $content = file_get_contents("/var/log/" . $logFile);
    echo "<pre>" . $content . "</pre>";
}
