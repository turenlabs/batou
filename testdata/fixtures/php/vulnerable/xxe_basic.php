<?php
// XXE (XML External Entity) injection via simplexml_load_string.
// Vulnerable: external entity loading is not disabled.

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $xml_input = file_get_contents("php://input");

    // GTSS: XXE via simplexml_load_string with external entities enabled
    $xml = simplexml_load_string($xml_input);

    if ($xml !== false) {
        echo "Parsed XML:<br>";
        echo "Name: " . $xml->name . "<br>";
        echo "Email: " . $xml->email . "<br>";
    } else {
        echo "Failed to parse XML.";
    }
}

// DOMDocument variant - also vulnerable without disabling entities
if (isset($_POST['xml_data'])) {
    $doc = new DOMDocument();
    $doc->loadXML($_POST['xml_data']);

    $names = $doc->getElementsByTagName("name");
    foreach ($names as $name) {
        echo "Found: " . $name->nodeValue . "<br>";
    }
}

// simplexml_load_file variant
if (isset($_GET['xml_url'])) {
    $xml = simplexml_load_file($_GET['xml_url']);
    echo $xml->asXML();
}
