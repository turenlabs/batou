<?php
$name = $_GET['name'];
echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
?>