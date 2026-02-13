<?php
// GTSS-PHP-009: Twig raw filter and autoescape disabled

// Vulnerable: raw filter bypasses auto-escaping
$template = "{{ user_comment | raw }}";

// Vulnerable: autoescape disabled
$block = "{% autoescape false %}{{ user_input }}{% endautoescape %}";

// Vulnerable: autoescape disabled in config
$twig = new \Twig\Environment($loader, [
    'autoescape' => false,
]);
