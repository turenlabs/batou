<?php
// Code injection via eval() with user-controlled input.
// Vulnerable: eval executes arbitrary PHP code.

// GTSS-INJ-003: eval() with variable from user input
if (isset($_GET['code'])) {
    $code = $_GET['code'];
    eval($code);
}

// Calculator-style eval injection
if (isset($_POST['expression'])) {
    $expr = $_POST['expression'];
    // Attacker can inject: 1; system('id');
    eval('$result = ' . $expr . ';');
    echo "Result: " . $result;
}

// Dynamic class method invocation via eval
$method = $_GET['method'];
$args = $_GET['args'];
eval("\$obj->$method($args);");

// assert() can also execute code in older PHP versions
if (isset($_GET['check'])) {
    $check = $_GET['check'];
    assert($check);
}

// Variable variables - indirect code execution
$var_name = $_GET['var'];
$$var_name = $_GET['value'];
