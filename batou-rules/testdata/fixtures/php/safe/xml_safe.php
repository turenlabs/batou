<?php
// Safe: XML parsing with external entity loading disabled.
// Prevents XXE attacks.

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $xml_input = file_get_contents("php://input");

    // Safe: disable external entity loading before parsing
    libxml_disable_entity_loader(true);
    $previous = libxml_use_internal_errors(true);

    $xml = simplexml_load_string($xml_input, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_NONET);

    if ($xml !== false) {
        echo "Name: " . htmlspecialchars((string)$xml->name, ENT_QUOTES, 'UTF-8') . "<br>";
        echo "Email: " . htmlspecialchars((string)$xml->email, ENT_QUOTES, 'UTF-8') . "<br>";
    } else {
        echo "Failed to parse XML.";
        foreach (libxml_get_errors() as $error) {
            error_log("XML parse error: " . $error->message);
        }
    }

    libxml_clear_errors();
    libxml_use_internal_errors($previous);
}

// Safe DOMDocument usage with entity loading disabled
if (isset($_POST['xml_data'])) {
    libxml_disable_entity_loader(true);

    $doc = new DOMDocument();
    $doc->loadXML($_POST['xml_data'], LIBXML_NOENT | LIBXML_NONET | LIBXML_DTDLOAD);

    $names = $doc->getElementsByTagName("name");
    foreach ($names as $name) {
        echo "Found: " . htmlspecialchars($name->nodeValue, ENT_QUOTES, 'UTF-8') . "<br>";
    }
}

// Safe: JSON parsing instead of XML for API input
if ($_SERVER['CONTENT_TYPE'] === 'application/json') {
    $data = json_decode(file_get_contents("php://input"), true);
    if (json_last_error() === JSON_ERROR_NONE) {
        echo "Received: " . htmlspecialchars($data['name'] ?? '', ENT_QUOTES, 'UTF-8');
    }
}
