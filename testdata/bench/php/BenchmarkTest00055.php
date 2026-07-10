<?php
$id = intval($_GET['id']);
exec("process --id=" . $id);
?>