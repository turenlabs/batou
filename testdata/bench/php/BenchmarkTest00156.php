<?php
$next = $_GET['next'];
$safe = filter_var($next, FILTER_SANITIZE_URL);
$parsed = parse_url($safe);
if (!isset($parsed['host'])) {
    header("Location: " . $safe);
}
?>