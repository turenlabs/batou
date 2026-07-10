<?php
$doc = $_GET['doc'];
$base = realpath("/docs");
$full = realpath("/docs/" . $doc);
if ($full && strpos($full, $base) === 0) {
    readfile($full);
}
?>