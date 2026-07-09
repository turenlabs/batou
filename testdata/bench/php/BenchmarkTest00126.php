<?php
require_once 'vendor/autoload.php';
$loader = new \Twig\Loader\ArrayLoader([]);
$twig = new \Twig\Environment($loader);
$userTpl = $_POST['body'];
echo $twig->createTemplate($userTpl)->render(['name' => 'test']);
?>