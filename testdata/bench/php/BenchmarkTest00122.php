<?php
require_once 'vendor/autoload.php';
$loader = new \Twig\Loader\ArrayLoader([]);
$twig = new \Twig\Environment($loader);
$param = $_GET['tpl'];
$tmpl = $twig->createTemplate($param);
echo $tmpl->render([]);
?>