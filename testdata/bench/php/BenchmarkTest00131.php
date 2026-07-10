<?php
require_once 'vendor/autoload.php';
$loader = new \Twig\Loader\FilesystemLoader('/templates');
$twig = new \Twig\Environment($loader);
$name = $_GET['name'];
echo $twig->render('hello.twig', ['name' => $name]);
?>