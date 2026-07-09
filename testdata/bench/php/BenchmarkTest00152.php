<?php
$page = $_GET['page'];
$allowed = ['/home', '/about', '/contact', '/dashboard'];
if (in_array($page, $allowed)) {
    header("Location: " . $page);
    exit;
}
header("Location: /home");
?>