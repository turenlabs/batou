<?php
$id = intval($_GET['id']);
header("Location: /users/" . $id);
exit;
?>