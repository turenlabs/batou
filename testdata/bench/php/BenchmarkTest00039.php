<?php
$q = $_GET['q'];
echo '<a href="/search?q=' . urlencode($q) . '">Search</a>';
?>