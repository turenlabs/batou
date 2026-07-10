<?php
require_once 'vendor/autoload.php';
$loader = new \Twig\Loader\ArrayLoader([]);
$twig = new \Twig\Environment($loader);
$input = $_POST['template'];
echo $twig->createTemplate($input)->render([]);
?>