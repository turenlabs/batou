<?php
$name = $_GET['name'];
$template = file_get_contents("/templates/page.html");
echo str_replace("{{name}}", htmlspecialchars($name), $template);
?>