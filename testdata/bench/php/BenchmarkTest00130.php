<?php
require_once 'vendor/autoload.php';
$loader = new \Twig\Loader\ArrayLoader([]);
$twig = new \Twig\Environment($loader);
$user = $_GET['user'];
$tmpl = $twig->createTemplate($user);
echo $tmpl->render([]);
?>
