<?php
$name = filter_input(INPUT_GET, 'name', FILTER_SANITIZE_SPECIAL_CHARS);
echo "<p>" . $name . "</p>";
?>