<?php
$slug = $_GET['slug'];
if (preg_match('/^[a-z0-9-]+$/', $slug)) {
    header("Location: /articles/" . $slug);
    exit;
}
header("Location: /");
?>