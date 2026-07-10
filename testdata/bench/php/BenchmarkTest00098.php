<?php
$slug = $_GET['slug'];
if (preg_match('/^[a-zA-Z0-9_-]+$/', $slug)) {
    $url = "https://cdn.example.com/files/" . $slug;
    echo file_get_contents($url);
}
?>