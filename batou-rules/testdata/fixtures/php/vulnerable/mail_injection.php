<?php
// GTSS-PHP-004: Mail header injection

function send_contact_form() {
    $to = $_POST['email'];
    $subject = $_POST['subject'];
    $message = $_POST['message'];
    $from = $_POST['from'];

    // Vulnerable: user input in mail headers
    mail($to, $subject, $message, "From: " . $from);
}

function send_feedback() {
    // Vulnerable: all params from user input
    mail($_POST['to'], $_POST['subject'], $_POST['body'], $_POST['headers']);
}
