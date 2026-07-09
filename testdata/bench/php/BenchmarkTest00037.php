<?php
$comment = $_POST['comment'];
echo "<p>" . htmlspecialchars($comment, ENT_QUOTES, 'UTF-8') . "</p>";
?>