<?php
$raw = $_POST['payload'];
$decoded = json_decode($raw);
if ($decoded !== null && isset($decoded->type)) {
    handle($decoded);
}
?>