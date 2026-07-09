<?php
$data = $_POST['data'];
$parsed = json_decode($data, true);
if (json_last_error() === JSON_ERROR_NONE) {
    process($parsed);
}
?>