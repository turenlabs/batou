<?php
$page = $_GET['page'];
$allowed = ['home', 'about', 'contact'];
if (in_array($page, $allowed)) {
    include("pages/" . $page . ".php");
}
?>