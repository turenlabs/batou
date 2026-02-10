<?php
// Insecure deserialization via unserialize() on user input.
// Vulnerable: unserialize can trigger magic methods for RCE.

class FileHandler {
    public $filename;
    public $content;

    public function __destruct() {
        if ($this->filename) {
            file_put_contents($this->filename, $this->content);
        }
    }
}

class Logger {
    public $logFile;
    public $message;

    public function __wakeup() {
        file_put_contents($this->logFile, $this->message, FILE_APPEND);
    }
}

// GTSS: unserialize with user input - insecure deserialization
if (isset($_COOKIE['user_prefs'])) {
    $prefs = unserialize($_COOKIE['user_prefs']);
    echo "Welcome back! Your preferences have been loaded.";
}

// Another vector: POST data
if (isset($_POST['data'])) {
    $data = unserialize(base64_decode($_POST['data']));
    echo "Data processed: " . print_r($data, true);
}

// GET parameter deserialization
$session_data = $_GET['session'];
$obj = unserialize($session_data);
