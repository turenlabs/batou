<?php
require_once 'vendor/autoload.php';
$loader = new \Twig\Loader\ArrayLoader([]);
$twig = new \Twig\Environment($loader);
$template = $_GET['template'];
$tmpl = $twig->createTemplate($template);
echo $tmpl->render([]);
?>