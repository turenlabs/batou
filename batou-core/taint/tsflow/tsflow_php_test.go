package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PHP sanitizer tests — FileRead, Log, Template, Header, LDAP, XPath, TrustBoundary
// =========================================================================

// realpath() alone is NOT a sanitizer: realpath("../../etc/passwd")
// resolves to "/etc/passwd" — a real path OUTSIDE the safe base. The taint
// flow must survive. (This test previously asserted the opposite, which was
// unsound — see the filepath.Clean note in go_sanitizers.go and the
// os.path.normpath/realpath note in python_sanitizers.go; only canonicalize
// + containment, e.g. strpos(realpath($p), $base) === 0, is a defence. The
// sink is readfile because file_get_contents is catalogued as SnkURLFetch —
// it accepts URLs — which made the old no-FileRead assertion vacuous.)
func TestPHP_FileRead_Realpath_NotASanitizer(t *testing.T) {
	code := `<?php
function handler() {
    $file = $_GET["file"];
    $safe = realpath($file);
    readfile($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("realpath() alone must NOT neutralize FileRead taint — expected the traversal flow to still fire")
	}
}

func TestPHP_FileRead_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $file = $_GET["file"];
    readfile($file);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for $_GET -> readfile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_FileRead_Sanitized_Basename(t *testing.T) {
	code := `<?php
function handler() {
    $file = $_GET["file"];
    $safe = basename($file);
    $content = file_get_contents($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("basename() should neutralize file read taint flow")
	}
}

func TestPHP_Log_Sanitized_Monolog(t *testing.T) {
	code := `<?php
function handler() {
    $input = $_POST["msg"];
    $logger->info("user action", ["data" => $input]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("Monolog structured logging with context array should neutralize log injection taint flow")
	}
}

func TestPHP_Log_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $input = $_POST["msg"];
    error_log($input);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for $_POST -> error_log")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_LDAP_Sanitized_LdapEscape(t *testing.T) {
	code := `<?php
function handler() {
    $user = $_GET["user"];
    $safe = ldap_escape($user);
    $result = ldap_search($conn, "dc=example,dc=com", "(uid=" . $safe . ")");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("ldap_escape() should neutralize LDAP injection taint flow")
	}
}

func TestPHP_LDAP_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $user = $_GET["user"];
    $result = ldap_search($conn, "dc=example,dc=com", "(uid=" . $user . ")");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for $_GET -> ldap_search")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// PHP LDAP injection tests — ldap_list, ldap_add, ldap_bind DN injection
// =========================================================================

func TestPHP_LDAP_List_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $filter = $_GET["filter"];
    $result = ldap_list($conn, "dc=example,dc=com", "(cn=" . $filter . ")");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for $_GET -> ldap_list")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_LDAP_List_Sanitized(t *testing.T) {
	code := `<?php
function handler() {
    $filter = $_GET["filter"];
    $safe = ldap_escape($filter);
    $result = ldap_list($conn, "dc=example,dc=com", "(cn=" . $safe . ")");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("ldap_escape() should neutralize LDAP injection via ldap_list")
	}
}

func TestPHP_LDAP_Read_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $user = $_POST["user"];
    $result = ldap_read($conn, "dc=example,dc=com", "(uid=" . $user . ")");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for $_POST -> ldap_read")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_LDAP_Bind_DN_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $dn = $_POST["username"];
    ldap_bind($conn, "cn=" . $dn . ",dc=example,dc=com", $password);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for $_POST -> ldap_bind")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_LDAP_Add_DN_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $ou = $_GET["ou"];
    $dn = "cn=newuser,ou=" . $ou . ",dc=example,dc=com";
    $entry = ["cn" => "newuser", "sn" => "User"];
    ldap_add($conn, $dn, $entry);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for $_GET -> ldap_add")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_LDAP_Delete_DN_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $cn = $_POST["cn"];
    ldap_delete($conn, "cn=" . $cn . ",dc=example,dc=com");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for $_POST -> ldap_delete")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_LDAP_Rename_DN_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $cn = $_GET["cn"];
    ldap_rename($conn, "cn=" . $cn . ",dc=example,dc=com", "cn=newname", "dc=example,dc=com", true);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP DN injection flow for $_GET -> ldap_rename")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_LDAP_Bind_DN_Sanitized(t *testing.T) {
	code := `<?php
function handler() {
    $dn = $_POST["username"];
    $safe = ldap_escape($dn, "", LDAP_ESCAPE_DN);
    ldap_bind($conn, "cn=" . $safe . ",dc=example,dc=com", $password);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("ldap_escape() should neutralize LDAP DN injection via ldap_bind")
	}
}

func TestPHP_Header_Sanitized_SymfonyResponse(t *testing.T) {
	code := `<?php
function handler() {
    $val = $_GET["redirect"];
    $response->headers->set("Location", $val);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("Symfony Response headers->set() should neutralize header injection taint flow")
	}
}

func TestPHP_Header_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $val = $_GET["redirect"];
    header("Location: " . $val);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	// A tainted header("Location: ...") is the open-redirect (CWE-601 /
	// SnkRedirect) shape — the php.header.location sink (ordered ahead of the
	// generic CWE-113 php.header sink) gives it the more-specific classification.
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for $_GET -> header(\"Location: \")")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Template_Sanitized_HTMLPurifier(t *testing.T) {
	code := `<?php
function handler() {
    $input = $_POST["content"];
    $safe = $purifier->purify($input);
    echo $twig->render("template.html", ["content" => $safe]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("HTMLPurifier->purify() should neutralize template injection taint flow")
	}
}

func TestPHP_XPath_Sanitized_Intval(t *testing.T) {
	code := `<?php
function handler() {
    $id = $_GET["id"];
    $safe = intval($id);
    $DOMXPath = new DOMXPath($doc);
    $result = $DOMXPath->query("/users/user[@id=" . $safe . "]");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("intval() should neutralize XPath injection taint flow")
	}
}

func TestPHP_XPath_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $id = $_GET["id"];
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $DOMXPath = new DOMXPath($doc);
    $result = $DOMXPath->query("/users/user[@id=" . $id . "]");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for $_GET -> DOMXPath->query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_TrustBoundary_Sanitized_FilterVar(t *testing.T) {
	// filter_var() carries developer intent to validate, so tsflow treats it
	// as a TrustBoundary sanitizer. (SQL/Command/HTML are NOT cleared — see
	// sanitizer_context_test.go in batou-core/taint/ for those guards.)
	code := `<?php
function handler() {
    $val = $_POST["env_val"];
    $safe = filter_var($val, FILTER_VALIDATE_INT);
    putenv("APP_MODE=" . $safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("filter_var(..., FILTER_VALIDATE_INT) should neutralize trust boundary taint flow")
	}
}

func TestPHP_TrustBoundary_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $val = $_POST["env_val"];
    putenv("APP_MODE=" . $val);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for $_POST -> putenv")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// PHP SrcNetwork tests — curl, Guzzle, WordPress, Laravel, sockets
// =========================================================================

func TestPHP_Network_CurlExec_SQLInjection(t *testing.T) {
	code := `<?php
function handler($pdo) {
    $ch = curl_init("https://api.example.com/data");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    $pdo->query("SELECT * FROM users WHERE name = '" . $response . "'");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for curl_exec() response -> PDO::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Network_CurlExec_XSS(t *testing.T) {
	code := `<?php
function handler() {
    $ch = curl_init("https://api.example.com/data");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $data = curl_exec($ch);
    printf($data);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for curl_exec() response -> printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Network_CurlExec_Sanitized(t *testing.T) {
	code := `<?php
function handler() {
    $ch = curl_init("https://api.example.com/data");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $data = curl_exec($ch);
    $safe = htmlspecialchars($data, ENT_QUOTES, "UTF-8");
    printf($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("htmlspecialchars() should neutralize XSS from curl_exec() response")
	}
}

func TestPHP_Network_GuzzleGetBody_SQLInjection(t *testing.T) {
	code := `<?php
function handler($pdo) {
    $client = new GuzzleHttp\Client();
    $response = $client->get("https://api.example.com/users");
    $body = $response->getBody();
    $pdo->query("SELECT * FROM logs WHERE data = '" . $body . "'");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Guzzle getBody() -> PDO::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Network_WordPressRemoteGet_XSS(t *testing.T) {
	code := `<?php
function handler() {
    $response = wp_remote_get("https://api.example.com/widget");
    $body = wp_remote_retrieve_body($response);
    printf($body);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for wp_remote_retrieve_body() -> printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Network_CurlMultiGetContent_SQLInjection(t *testing.T) {
	code := `<?php
function handler($pdo) {
    $ch = curl_init("https://api.example.com/data");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $mh = curl_multi_init();
    curl_multi_add_handle($mh, $ch);
    curl_multi_exec($mh, $active);
    $data = curl_multi_getcontent($ch);
    $pdo->query("SELECT * FROM logs WHERE data = '" . $data . "'");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for curl_multi_getcontent() -> PDO::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Network_SocketRead_CommandInjection(t *testing.T) {
	code := `<?php
function handler() {
    $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    socket_connect($sock, "10.0.0.1", 8080);
    $data = socket_read($sock, 2048);
    exec("process " . $data);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for socket_read() -> exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Network_StreamGetContents_CommandInjection(t *testing.T) {
	code := `<?php
function handler() {
    $fp = fopen("https://api.example.com/data", "r");
    $data = stream_get_contents($fp);
    exec("process " . $data);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for stream_get_contents() -> exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// PHP NoSQL / MongoDB injection tests (CWE-943)
// =========================================================================

func TestPHP_MongoDB_FindOne_NoSQLInjection(t *testing.T) {
	code := `<?php
function handler() {
    $collection = getCollection();
    $filter = $_POST["filter"];
    $user = $collection->findOne($filter);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for $_POST -> Collection->findOne()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_MongoDB_Find_NoSQLInjection(t *testing.T) {
	code := `<?php
function handler() {
    $collection = getCollection();
    $filter = $_POST["filter"];
    $results = $collection->find($filter);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for $_POST -> Collection->find()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_MongoDB_UpdateOne_NoSQLInjection(t *testing.T) {
	code := `<?php
function handler() {
    $collection = getCollection();
    $filter = $_GET["filter"];
    $collection->updateOne($filter, ['$set' => ["status" => "active"]]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for $_GET -> Collection->updateOne()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_MongoDB_DeleteOne_NoSQLInjection(t *testing.T) {
	code := `<?php
function handler() {
    $collection = getCollection();
    $filter = $_GET["filter"];
    $collection->deleteOne($filter);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for $_GET -> Collection->deleteOne()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_MongoDB_Aggregate_NoSQLInjection(t *testing.T) {
	code := `<?php
function handler() {
    $collection = getCollection();
    $pipeline = $_POST["pipeline"];
    $results = $collection->aggregate($pipeline);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for $_POST -> Collection->aggregate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_MongoDB_Driver_ExecuteCommand_NoSQLInjection(t *testing.T) {
	code := `<?php
function handler() {
    $manager = getManager();
    $cmd = $_POST["command"];
    $manager->executeCommand("mydb", $cmd);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for $_POST -> Manager->executeCommand()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_MongoDB_FindOne_Sanitized_ObjectId(t *testing.T) {
	code := `<?php
function handler() {
    $collection = getCollection();
    $id = $_GET["id"];
    $oid = new ObjectId($id);
    $user = $collection->findOne($oid);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("ObjectId conversion should neutralize NoSQL injection taint flow")
	}
}

func TestPHP_MongoDB_Find_Sanitized_Intval(t *testing.T) {
	code := `<?php
function handler() {
    $collection = getCollection();
    $age = $_GET["age"];
    $safe = intval($age);
    $users = $collection->find($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("intval() should neutralize NoSQL injection taint flow")
	}
}

// =========================================================================
// PHP sanitizer tests — Path traversal (FileRead/FileWrite)
// =========================================================================

// SplFileInfo::getRealPath() alone is NOT a sanitizer — like realpath(), it
// canonicalizes to a real path that can lie OUTSIDE the safe base; it does
// not reject escapes. The taint flow must survive. (Previously asserted the
// opposite — unsound; see TestPHP_FileRead_Realpath_NotASanitizer.)
func TestPHP_FileRead_GetRealPath_NotASanitizer(t *testing.T) {
	// Sink is readfile, not file_get_contents — the latter is catalogued as
	// SnkURLFetch (it accepts URLs), which made the old assertion vacuous.
	code := `<?php
function handler() {
    $path = $_GET["file"];
    $safe = $path->getRealPath();
    readfile($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("getRealPath() alone must NOT neutralize FileRead taint — expected the traversal flow to still fire")
	}
}

func TestPHP_FileWrite_GetRealPath_NotASanitizer(t *testing.T) {
	code := `<?php
function handler() {
    $path = $_POST["dest"];
    $safe = $path->getRealPath();
    file_put_contents($safe, "data");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("getRealPath() alone must NOT neutralize FileWrite taint — expected the traversal flow to still fire")
	}
}

func TestPHP_FileRead_Sanitized_PathinfoBasename(t *testing.T) {
	code := `<?php
function handler() {
    $file = $_GET["file"];
    $safe = pathinfo($file, PATHINFO_BASENAME);
    $content = file_get_contents($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("pathinfo(PATHINFO_BASENAME) should neutralize file read taint flow")
	}
}

func TestPHP_FileWrite_Sanitized_SanitizeFileName(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_POST["filename"];
    $safe = sanitize_file_name($name);
    file_put_contents($safe, "data");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("WordPress sanitize_file_name() should neutralize file write taint flow")
	}
}

// wp_normalize_path() alone is NOT a sanitizer — it only converts
// backslashes to forward slashes and collapses duplicate separators; "../"
// traversal sequences pass through untouched. The taint flow must survive.
// (Previously asserted the opposite — unsound; see
// TestPHP_FileRead_Realpath_NotASanitizer.)
func TestPHP_FileRead_WpNormalizePath_NotASanitizer(t *testing.T) {
	code := `<?php
function handler() {
    $path = $_GET["path"];
    $safe = wp_normalize_path($path);
    readfile($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("wp_normalize_path() alone must NOT neutralize FileRead taint — expected the traversal flow to still fire")
	}
}

// =========================================================================
// PHP sanitizer tests — Eval (SnkEval)
// =========================================================================

func TestPHP_Eval_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $code = $_GET["code"];
    eval($code);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for $_GET -> eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Eval_Sanitized_Intval(t *testing.T) {
	code := `<?php
function handler() {
    $input = $_GET["num"];
    $safe = intval($input);
    eval($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("intval() should neutralize eval taint flow")
	}
}

// NOTE: the former TestPHP_Eval_Sanitized_{IsNumeric,CtypeAlnum} tests were
// removed with the unsound php.is_numeric / php.ctype catalog entries. Those
// predicates return a bool and transform nothing, so `$safe = is_numeric($x);
// eval($safe)` only looked clean because the bool is inert — it did not prove
// the entry sanitized $x. The SOUND guarded form (`if (is_numeric($x)) {...}`)
// is covered by the barrier-guard engine tests (TestBG_PHP_IsNumeric_Guarded_*,
// TestBG_PHP_CtypeAlnum_Command_Silent in barrier_guards_php_ruby_test.go).

// =========================================================================
// PHP sanitizer tests — Deserialization (SnkDeserialize)
// =========================================================================

func TestPHP_Deser_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $data = $_POST["data"];
    $obj = unserialize($data);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialize flow for $_POST -> unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// PHP sanitizer tests — SSRF (SnkURLFetch)
// =========================================================================

func TestPHP_SSRF_Unsanitized(t *testing.T) {
	code := `<?php
function handler() {
    $url = $_GET["url"];
    $response = file_get_contents($url);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $_GET -> file_get_contents(url)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_SSRF_Sanitized_WpSafeRemoteGet(t *testing.T) {
	// wp_safe_remote_get is a safe wrapper — its return value is sanitized
	code := `<?php
function handler() {
    $url = $_GET["url"];
    $safe = wp_safe_remote_get($url);
    file_get_contents($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("wp_safe_remote_get() should neutralize SSRF taint flow")
	}
}

func TestPHP_SSRF_Sanitized_WpSafeRemotePost(t *testing.T) {
	code := `<?php
function handler() {
    $url = $_POST["url"];
    $safe = wp_safe_remote_post($url);
    file_get_contents($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("wp_safe_remote_post() should neutralize SSRF taint flow")
	}
}

func TestPHP_SSRF_Sanitized_Ip2long(t *testing.T) {
	// ip2long converts IP to integer — sanitized result cannot be a URL
	code := `<?php
function handler() {
    $host = $_GET["host"];
    $safe = ip2long($host);
    file_get_contents($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("ip2long() should neutralize SSRF taint flow")
	}
}

func TestPHP_SSRF_Sanitized_InetPton(t *testing.T) {
	// inet_pton converts IP to binary — sanitized result cannot be a URL
	code := `<?php
function handler() {
    $host = $_GET["host"];
    $safe = inet_pton($host);
    file_get_contents($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("inet_pton() should neutralize SSRF taint flow")
	}
}
