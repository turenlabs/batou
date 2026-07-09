<?php
$input = $_GET['input'];
$clean = strip_tags($input);
echo "<p>" . $clean . "</p>";
?>