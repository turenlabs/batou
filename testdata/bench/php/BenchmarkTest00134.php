<?php
require_once 'vendor/autoload.php';
$loader = new \Twig\Loader\FilesystemLoader('/templates');
$twig = new \Twig\Environment($loader, ['autoescape' => 'html']);
echo $twig->render('profile.twig', ['user' => $_GET['user']]);
?>