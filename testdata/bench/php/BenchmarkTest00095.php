<?php
$id = intval($_GET['id']);
$url = "https://api.example.com/users/" . $id;
$data = file_get_contents($url);
echo $data;
?>