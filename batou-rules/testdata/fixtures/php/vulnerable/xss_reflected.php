<?php
// DVWA-style reflected XSS.
// Vulnerable: user input echoed directly without escaping.

$name = $_GET['name'];

?>
<!DOCTYPE html>
<html>
<head><title>Greeting Page</title></head>
<body>

<?php
// GTSS-XSS-011 / GTSS-XSS-004: Reflected XSS via echo of $_GET
echo "<h1>Hello, " . $name . "</h1>";
?>

<form method="GET" action="">
    <label for="name">Enter your name:</label>
    <input type="text" id="name" name="name" />
    <input type="submit" value="Submit" />
</form>

<?php
// Another reflected XSS pattern
if (isset($_GET['search'])) {
    echo "<p>Search results for: " . $_GET['search'] . "</p>";
}

// Direct echo of superglobal
echo $_POST['comment'];
?>

</body>
</html>
