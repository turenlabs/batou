<?php
require_once 'vendor/autoload.php';
$loader = new \Twig\Loader\ArrayLoader(['page' => '<h1>{{ title }}</h1>']);
$twig = new \Twig\Environment($loader, ['autoescape' => 'html']);
echo $twig->render('page', ['title' => $_GET['title']]);
?>