<?php
$data = $_GET['data'];
echo "<script>var d = " . json_encode($data) . ";</script>";
?>