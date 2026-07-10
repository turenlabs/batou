<?php
$input = $_POST['cache'];
$item = unserialize($input);
save_cache($item);
?>