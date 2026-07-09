<?php
require_once 'vendor/autoload.php';
$loader = new \Twig\Loader\ArrayLoader([]);
$twig = new \Twig\Environment($loader);
$data = $_COOKIE['tmpl'];
echo $twig->createTemplate($data)->render(['name' => 'world']);
?>