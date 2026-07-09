<?php
// SSTI (CWE-1336): Twig Environment::createTemplate() compiles a user-controlled
// string into an executable template. Detected at the AST tier (BATOU-PHPAST-007).

function renderUserTemplate(\Twig\Environment $twig, $request) {
    $input = $request->get('tpl');
    $template = $twig->createTemplate($input);
    return $template->render([]);
}

// Second-order / stored shape: the template body is read from a DB row. Taint
// cannot connect it to a request source, but the AST tier still flags the
// structural SSTI sink.
function renderStoredTemplate(\Twig\Environment $twig, $db) {
    $row = $db->query("SELECT body FROM email_templates WHERE id = 1")->fetch();
    $body = $row['body'];
    $template = $twig->createTemplate($body);
    return $template->render([]);
}

// Laravel Blade string compilation from an indirect variable.
function compileSnippet($blade, $cfg) {
    $snippet = $cfg->get('layout.snippet');
    return $blade->compileString($snippet);
}
