<?php
require_once 'vendor/autoload.php';
$loader = new \Twig\Loader\ArrayLoader([]);
$twig = new \Twig\Environment($loader);
$data = $_GET['data'];
echo $twig->createTemplate($data)->render([]);
?>