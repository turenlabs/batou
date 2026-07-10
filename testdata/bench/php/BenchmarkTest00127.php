<?php
require_once 'vendor/autoload.php';
$loader = new \Twig\Loader\ArrayLoader([]);
$twig = new \Twig\Environment($loader);
$param = $_REQUEST['tpl'];
echo $twig->createTemplate($param)->render(['user' => 'test']);
?>