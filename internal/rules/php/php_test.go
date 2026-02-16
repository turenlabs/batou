package php

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// ==========================================================================
// BATOU-PHP-001: Type Juggling
// ==========================================================================

func TestPHP001_LooseComparePassword(t *testing.T) {
	content := `<?php
if ($password == $stored_hash) {
    login($user);
}`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-001")
}

func TestPHP001_LooseCompareToken(t *testing.T) {
	content := `<?php
if ($token != $expected_token) {
    die("Invalid token");
}`
	result := testutil.ScanContent(t, "/app/verify.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-001")
}

func TestPHP001_StrictCompare_Safe(t *testing.T) {
	content := `<?php
if ($password === $stored_hash) {
    login($user);
}`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-001")
}

func TestPHP001_HashEquals_Safe(t *testing.T) {
	content := `<?php
if (hash_equals($stored_hash, $password)) {
    login($user);
}`
	result := testutil.ScanContent(t, "/app/auth.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-001")
}

// ==========================================================================
// BATOU-PHP-002: SSRF via file_get_contents/fopen
// ==========================================================================

func TestPHP002_FileGetContentsVar(t *testing.T) {
	content := `<?php
$url = $_GET['url'];
$data = file_get_contents($url);
echo $data;`
	result := testutil.ScanContent(t, "/app/proxy.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-002")
}

func TestPHP002_FopenVar(t *testing.T) {
	content := `<?php
$handle = fopen($url, 'r');
$content = fread($handle, 8192);`
	result := testutil.ScanContent(t, "/app/fetch.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-002")
}

func TestPHP002_CurlSetopt(t *testing.T) {
	content := `<?php
curl_setopt($ch, CURLOPT_URL, $userUrl);
curl_exec($ch);`
	result := testutil.ScanContent(t, "/app/curl.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-002")
}

func TestPHP002_FileGetContents_StaticPath_Safe(t *testing.T) {
	content := `<?php
$data = file_get_contents(__DIR__ . '/config.json');`
	result := testutil.ScanContent(t, "/app/config.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-002")
}

// ==========================================================================
// BATOU-PHP-003: File Inclusion (LFI/RFI)
// ==========================================================================

func TestPHP003_IncludeGetParam(t *testing.T) {
	content := `<?php
include($_GET['page']);`
	result := testutil.ScanContent(t, "/app/router.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-003")
}

func TestPHP003_RequireOnceConcat(t *testing.T) {
	content := `<?php
require_once("templates/" . $template);`
	result := testutil.ScanContent(t, "/app/render.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-003")
}

func TestPHP003_IncludeStaticPath_Safe(t *testing.T) {
	content := `<?php
include("header.php");
require_once(__DIR__ . '/config.php');`
	result := testutil.ScanContent(t, "/app/layout.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-003")
}

// ==========================================================================
// BATOU-PHP-004: mail() Header Injection
// ==========================================================================

func TestPHP004_MailWithGetParam(t *testing.T) {
	content := `<?php
$to = $_POST['email'];
$subject = $_POST['subject'];
mail($to, $subject, $message, "From: " . $_POST['from']);`
	result := testutil.ScanContent(t, "/app/contact.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-004")
}

func TestPHP004_MailHeaderParam(t *testing.T) {
	content := `<?php
mail($email, $subject, $body, $header);`
	result := testutil.ScanContent(t, "/app/mailer.php", content)
	// No superglobal nearby, should not trigger
	testutil.MustNotFindRule(t, result, "BATOU-PHP-004")
}

// ==========================================================================
// BATOU-PHP-005: Command Injection
// ==========================================================================

func TestPHP005_SystemWithInput(t *testing.T) {
	content := `<?php
system($cmd);`
	result := testutil.ScanContent(t, "/app/exec.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-005")
}

func TestPHP005_ExecWithGetParam(t *testing.T) {
	content := `<?php
exec($command . " " . $_GET['file']);`
	result := testutil.ScanContent(t, "/app/run.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-005")
}

func TestPHP005_EscapedCommand_Safe(t *testing.T) {
	content := `<?php
$safe = escapeshellarg($_GET['file']);
exec("ls " . $safe);`
	result := testutil.ScanContent(t, "/app/safe_exec.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-005")
}

// ==========================================================================
// BATOU-PHP-006: Raw SQL Query
// ==========================================================================

func TestPHP006_MysqliQueryInterp(t *testing.T) {
	content := `<?php
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");`
	result := testutil.ScanContent(t, "/app/db.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-006")
}

func TestPHP006_PgQueryConcat(t *testing.T) {
	content := `<?php
$result = pg_query($conn, "SELECT * FROM users WHERE name = '" . $name . "'");`
	result := testutil.ScanContent(t, "/app/db.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-006")
}

func TestPHP006_PreparedStatement_Safe(t *testing.T) {
	content := `<?php
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();`
	result := testutil.ScanContent(t, "/app/db.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-006")
}

// ==========================================================================
// BATOU-PHP-007: Insecure Session Cookie
// ==========================================================================

func TestPHP007_SessionCookieHttpOnlyOff(t *testing.T) {
	content := `<?php
ini_set('session.cookie_httponly', 0);
session_start();`
	result := testutil.ScanContent(t, "/app/session.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-007")
}

func TestPHP007_SessionCookieSecureOff(t *testing.T) {
	content := `<?php
ini_set('session.cookie_secure', false);
session_start();`
	result := testutil.ScanContent(t, "/app/session.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-007")
}

func TestPHP007_SessionCookieSecure_Safe(t *testing.T) {
	content := `<?php
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
session_start();`
	result := testutil.ScanContent(t, "/app/session.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-007")
}

// ==========================================================================
// BATOU-PHP-008: Symfony Process Injection
// ==========================================================================

func TestPHP008_ProcessFromShellCommandline(t *testing.T) {
	content := `<?php
$process = Process::fromShellCommandline($command);
$process->run();`
	result := testutil.ScanContent(t, "/app/worker.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-008")
}

func TestPHP008_NewProcessWithVar(t *testing.T) {
	content := `<?php
$process = new Process([$cmd, $arg]);
$process->run();`
	result := testutil.ScanContent(t, "/app/worker.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-008")
}

func TestPHP008_ProcessStaticArgs_Safe(t *testing.T) {
	content := `<?php
$process = new Process(['ls', '-la', '/tmp']);
$process->run();`
	result := testutil.ScanContent(t, "/app/worker.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-008")
}

// ==========================================================================
// BATOU-PHP-009: Twig Raw Filter
// ==========================================================================

func TestPHP009_TwigRawFilter(t *testing.T) {
	content := `<?php
// Twig template rendering
$html = "{{ user_input | raw }}";`
	result := testutil.ScanContent(t, "/app/template.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-009")
}

func TestPHP009_TwigAutoescapeOff(t *testing.T) {
	content := `<?php
$twig = "{% autoescape false %}{{ content }}{% endautoescape %}";`
	result := testutil.ScanContent(t, "/app/template.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-009")
}

func TestPHP009_TwigAutoescapeConfigOff(t *testing.T) {
	content := `<?php
$twig = new \Twig\Environment($loader, [
    'autoescape' => false,
]);`
	result := testutil.ScanContent(t, "/app/twig_config.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-009")
}

// ==========================================================================
// BATOU-PHP-010: LDAP Injection
// ==========================================================================

func TestPHP010_LdapSearchVarFilter(t *testing.T) {
	content := `<?php
$filter = "(uid=" . $username . ")";
$result = ldap_search($conn, $base_dn, $filter);`
	result := testutil.ScanContent(t, "/app/ldap_auth.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-010")
}

func TestPHP010_LdapBindVarDN(t *testing.T) {
	content := `<?php
ldap_bind($conn, "uid=" . $username . ",ou=people,dc=example,dc=com", $password);`
	result := testutil.ScanContent(t, "/app/ldap_auth.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-010")
}

func TestPHP010_LdapEscape_Safe(t *testing.T) {
	content := `<?php
$safe_user = ldap_escape($username, '', LDAP_ESCAPE_FILTER);
$filter = "(uid=" . $safe_user . ")";
$result = ldap_search($conn, $base_dn, $filter);`
	result := testutil.ScanContent(t, "/app/ldap_auth.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-010")
}

// ==========================================================================
// BATOU-PHP-011: Weak Random
// ==========================================================================

func TestPHP011_RandForToken(t *testing.T) {
	content := `<?php
$token = rand(100000, 999999);
setcookie("csrf_token", $token);`
	result := testutil.ScanContent(t, "/app/csrf.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-011")
}

func TestPHP011_MtRandForPassword(t *testing.T) {
	content := `<?php
$password = '';
for ($i = 0; $i < 8; $i++) {
    $password .= chr(mt_rand(65, 90));
}`
	result := testutil.ScanContent(t, "/app/password_gen.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-011")
}

func TestPHP011_RandomInt_Safe(t *testing.T) {
	content := `<?php
$token = bin2hex(random_bytes(32));`
	result := testutil.ScanContent(t, "/app/token.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-011")
}

// ==========================================================================
// BATOU-PHP-012: Display Errors
// ==========================================================================

func TestPHP012_DisplayErrorsOn(t *testing.T) {
	content := `<?php
ini_set('display_errors', 1);`
	result := testutil.ScanContent(t, "/app/config.php", content)
	testutil.MustFindRule(t, result, "BATOU-PHP-012")
}

func TestPHP012_DisplayErrorsOff_Safe(t *testing.T) {
	content := `<?php
ini_set('display_errors', 0);
ini_set('log_errors', 1);`
	result := testutil.ScanContent(t, "/app/config.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-PHP-012")
}
