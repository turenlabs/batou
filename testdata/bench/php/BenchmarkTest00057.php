<?php
$ip = filter_input(INPUT_GET, 'ip', FILTER_VALIDATE_IP);
if ($ip !== false) {
    exec("ping -c 1 " . escapeshellarg($ip));
}
?>