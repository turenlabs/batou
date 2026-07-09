<?php
$data = $_REQUEST['info'];
$info = json_decode($data, true);
if (isset($info['name'])) {
    echo htmlspecialchars($info['name']);
}
?>