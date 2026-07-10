package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP flat-script (top-level) taint tests.
//
// The dominant real-world PHP idiom is a flat script with no enclosing
// function: a superglobal is read, threaded through interpolation /
// concatenation, and reaches a sink — all at file scope. Before the
// top-level walk these produced ZERO flows. echo/print are language
// statements (not call expressions) and were never seen as sinks. These
// tests lock in the recall and the matching FP-safe behaviour.
// =========================================================================

func TestPHP_TopLevel_SQLi_Interpolation(t *testing.T) {
	code := `<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '$id'";
mysqli_query($conn, $query);`
	flows := Analyze(code, "/var/www/index.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected top-level SQLi flow $_GET -> interpolated query -> mysqli_query")
	}
}

func TestPHP_TopLevel_XSS_EchoConcat(t *testing.T) {
	code := `<?php
$name = $_GET['name'];
echo "<h1>Hello, " . $name . "</h1>";`
	flows := Analyze(code, "/var/www/index.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow $_GET -> echo concat")
	}
}

func TestPHP_TopLevel_XSS_EchoConcat_Sanitized(t *testing.T) {
	code := `<?php
$name = $_GET['name'];
echo "<h1>Hello, " . htmlspecialchars($name) . "</h1>";`
	flows := Analyze(code, "/var/www/index.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("htmlspecialchars() inside echo must neutralize the XSS flow")
	}
}

func TestPHP_TopLevel_Print_DirectSuperglobal(t *testing.T) {
	code := `<?php print $_POST['comment'];`
	flows := Analyze(code, "/var/www/index.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for print of a direct superglobal")
	}
}

func TestPHP_TopLevel_InlineSourceAtSink(t *testing.T) {
	// $_GET passed directly into the sink with no intervening assignment.
	code := `<?php readfile($_GET['doc']);`
	flows := Analyze(code, "/var/www/index.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file-read flow for readfile($_GET[...]) inline source")
	}
}

func TestPHP_TopLevel_IfGuardBody_Walked(t *testing.T) {
	// The flow lives entirely inside an `if (isset(...)) { ... }` block.
	code := `<?php
if (isset($_GET['url'])) {
    $url = $_GET['url'];
    $content = file_get_contents($url);
}`
	flows := Analyze(code, "/var/www/index.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow inside an if(isset()) guard body")
	}
}

func TestPHP_TopLevel_SinkInIfCondition(t *testing.T) {
	// move_uploaded_file invoked as the if-condition; its tainted destination
	// arg must still flag.
	code := `<?php
$target = "uploads/";
$target .= basename($_FILES['x']['name']);
if (move_uploaded_file($_FILES['x']['tmp_name'], $target)) {
    echo "ok";
}`
	flows := Analyze(code, "/var/www/upload.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkUpload) {
		t.Error("expected upload flow for move_uploaded_file inside an if-condition")
	}
}

func TestPHP_TopLevel_DieGuard_ClearsTaint(t *testing.T) {
	// strpos containment guard + die() must clear taint on the safe
	// fall-through, so the subsequent fetch is NOT flagged.
	code := `<?php
$e = $_GET['endpoint'];
if (strpos($e, '..') !== false || $e[0] !== '/') {
    die("Invalid");
}
$url = 'https://api.example.com' . $e;
$response = file_get_contents($url);`
	flows := Analyze(code, "/var/www/proxy.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("strpos('..') + die() guard must clear taint on the safe path")
	}
}

func TestPHP_TopLevel_SafeUpload_NoFP(t *testing.T) {
	// MIME/extension allowlist + random rename: the move temp arg is benign
	// and the destination is not user-derived, so NO upload flow should fire.
	code := `<?php
$file = $_FILES['userfile'];
$ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
if (!in_array($ext, ['jpg', 'png'], true)) {
    die("Invalid extension.");
}
$new_name = bin2hex(random_bytes(16)) . '.' . $ext;
$target = "uploads/" . $new_name;
move_uploaded_file($file['tmp_name'], $target);`
	flows := Analyze(code, "/var/www/upload.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkUpload) {
		t.Error("safe upload (extension allowlist + random name) must not flag")
	}
}

func TestPHP_TopLevel_XXE_DisableEntityLoader_NoFP(t *testing.T) {
	code := `<?php
$xml_input = file_get_contents("php://input");
libxml_disable_entity_loader(true);
$xml = simplexml_load_string($xml_input, 'SimpleXMLElement', LIBXML_NONET);`
	flows := Analyze(code, "/var/www/xml.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("libxml_disable_entity_loader(true) must clear the XXE flow")
	}
}

func TestPHP_FinfoFile_NotPathTraversalSink(t *testing.T) {
	// $finfo->file() is MIME detection, not the global file() path sink.
	code := `<?php
$file = $_FILES['userfile'];
$finfo = new finfo(FILEINFO_MIME_TYPE);
$actual_type = $finfo->file($file['tmp_name']);`
	flows := Analyze(code, "/var/www/upload.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("$finfo->file() (MIME detection) must not match the global file() path-read sink")
	}
}

// TestPHP_PageHeaderMethod_NotHTTPHeaderSink guards against the same-name
// collision the global-builtin disambiguation exists to prevent: the global
// `header()` HTTP-response-header function (a CWE-113 sink) shares its name
// with a very common user-defined method. Grav's `$page->header()` returns the
// page front-matter object and `$this->header($response)` is a framework
// dispatch helper — neither sends an HTTP header. The global function is never
// called as `$obj->header(...)`, so a member call by that name is a collision.
func TestPHP_PageHeaderMethod_NotHTTPHeaderSink(t *testing.T) {
	code := `<?php
class Pages {
    public function dispatch($route) {
        $page = $this->find($route, true);
        if (isset($page->header()->access)) {
            $header = $page->header();
        }
        return $header;
    }
}`
	flows := Analyze(code, "/var/www/Pages.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("$page->header() (front-matter access) must not match the global header() HTTP-header sink")
	}
}

// TestPHP_GlobalHeader_StillFlags is the TP companion: the genuine global
// header() call with a tainted Location value must still flag — the
// member/scoped disambiguation only drops `$page->header()` front-matter access,
// never the bare global function call. A tainted `header("Location: ...")` is
// now classified as the more-specific open redirect (CWE-601 / SnkRedirect) by
// the php.header.location sink, which is ordered ahead of the generic CWE-113
// php.header sink.
func TestPHP_GlobalHeader_StillFlags(t *testing.T) {
	code := `<?php
$redirect_url = $_GET['url'];
header("Location: " . $redirect_url);`
	flows := Analyze(code, "/var/www/redir.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("global header() with a tainted Location must still flag (as an open redirect, SnkRedirect)")
	}
}
