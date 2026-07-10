<?php
$template = $_GET['tpl'];
if (preg_match('/^[a-zA-Z0-9_]+$/', $template)) {
    include("/templates/" . $template . ".php");
}
?>