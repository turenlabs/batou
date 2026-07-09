<?php
// SAFE: template strings are developer-authored literals, and user data is
// passed only as render context — never compiled as a template. The AST tier
// (BATOU-PHPAST-007) must NOT flag these.

function renderFixed(\Twig\Environment $twig, $request) {
    $name = $request->get('name');
    // Fixed literal template; user input is data, not template source.
    $template = $twig->createTemplate("Hello {{ name }}");
    return $template->render(['name' => $name]);
}

function renderTemplateFile(\Twig\Environment $twig, $request) {
    $name = $request->get('name');
    // Rendering a fixed template file with user data as context.
    return $twig->render('greeting.html.twig', ['name' => $name]);
}

function compileLiteral($blade) {
    return $blade->compileString("<p>{{ \$name }}</p>");
}
