<?php
$param = $_GET['param'];
if (preg_match('/^[a-zA-Z0-9]+$/', $param)) {
    exec("lookup " . escapeshellarg($param));
}
?>