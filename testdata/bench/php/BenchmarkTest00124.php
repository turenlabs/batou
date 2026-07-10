<?php
require_once 'vendor/autoload.php';
$loader = new \Twig\Loader\ArrayLoader([]);
$twig = new \Twig\Environment($loader);
$input = $_POST['body'];
$tmpl = $twig->createTemplate($input);
echo $tmpl->render(['name' => 'test']);
?>