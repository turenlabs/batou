package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PHP framework sanitizer tests — Laravel, Symfony, sodium/openssl
// =========================================================================

// --- Laravel crypto sanitizers (SnkCrypto) ---

func TestPHP_Crypto_Sanitized_LaravelHashMake(t *testing.T) {
	code := `<?php
use Illuminate\Support\Facades\Hash;

function register($request) {
    $password = $request->input("password");
    $hashed = Hash::make($password);
    return $hashed;
}
?>`
	flows := Analyze(code, "/app/AuthController.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("Hash::make() should neutralize crypto taint flow")
	}
}

func TestPHP_Crypto_Sanitized_LaravelHashCheck(t *testing.T) {
	code := `<?php
use Illuminate\Support\Facades\Hash;

function login($request) {
    $password = $request->input("password");
    $valid = Hash::check($password, $user->password);
    return $valid;
}
?>`
	flows := Analyze(code, "/app/AuthController.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("Hash::check() should neutralize crypto taint flow")
	}
}

func TestPHP_Crypto_Sanitized_LaravelCryptEncrypt(t *testing.T) {
	code := `<?php
use Illuminate\Support\Facades\Crypt;

function storeToken($request) {
    $token = $request->input("api_token");
    $encrypted = Crypt::encryptString($token);
    return $encrypted;
}
?>`
	flows := Analyze(code, "/app/TokenController.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("Crypt::encryptString() should neutralize crypto taint flow")
	}
}

func TestPHP_Crypto_Unsanitized_Md5(t *testing.T) {
	code := `<?php
function hashPassword() {
    $password = $_POST["password"];
    $hashed = md5($password);
    return $hashed;
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected crypto flow for $_POST -> md5()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- PHP native crypto sanitizers ---

func TestPHP_Crypto_Sanitized_OpensslEncrypt(t *testing.T) {
	code := `<?php
function encryptData() {
    $data = $_POST["secret"];
    $key = random_bytes(32);
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($data, "aes-256-gcm", $key, 0, $iv);
    return $encrypted;
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("openssl_encrypt() should neutralize crypto taint flow")
	}
}

func TestPHP_Crypto_Sanitized_SodiumPwhash(t *testing.T) {
	code := `<?php
function hashPassword() {
    $password = $_POST["password"];
    $hash = sodium_crypto_pwhash_str(
        $password,
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
        SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE
    );
    return $hash;
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("sodium_crypto_pwhash_str() should neutralize crypto taint flow")
	}
}

func TestPHP_Crypto_Sanitized_SodiumPwhashVerify(t *testing.T) {
	code := `<?php
function verifyPassword() {
    $password = $_POST["password"];
    $valid = sodium_crypto_pwhash_str_verify($storedHash, $password);
    return $valid;
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("sodium_crypto_pwhash_str_verify() should neutralize crypto taint flow")
	}
}

// --- Laravel trust boundary sanitizers (SnkTrustBoundary) ---

func TestPHP_TrustBoundary_Sanitized_LaravelGateAuthorize(t *testing.T) {
	code := `<?php
use Illuminate\Support\Facades\Gate;

function updatePost($request, $post) {
    $data = $request->input("title");
    Gate::authorize("update", $post);
    session()->put("last_edit", $data);
}
?>`
	flows := Analyze(code, "/app/PostController.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("Gate::authorize() should neutralize trust boundary taint flow")
	}
}

// --- Symfony trust boundary sanitizers ---

func TestPHP_TrustBoundary_Sanitized_SymfonyIsGranted(t *testing.T) {
	code := `<?php
function editProfile($request) {
    $data = $request->query->get("name");
    $checker = $this->container->get("security.authorization_checker");
    if ($checker->isGranted("ROLE_ADMIN")) {
        $session->set("name", $data);
    }
}
?>`
	flows := Analyze(code, "/app/ProfileController.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("isGranted() should neutralize trust boundary taint flow")
	}
}

func TestPHP_TrustBoundary_Sanitized_SymfonyDenyAccess(t *testing.T) {
	code := `<?php
function adminAction() {
    $input = $_GET["action"];
    $this->denyAccessUnlessGranted("ROLE_ADMIN");
    $_SESSION["action"] = $input;
}
?>`
	flows := Analyze(code, "/app/AdminController.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("denyAccessUnlessGranted() should neutralize trust boundary taint flow")
	}
}

func TestPHP_TrustBoundary_Unsanitized_Putenv(t *testing.T) {
	code := `<?php
function setEnv() {
    $input = $_GET["data"];
    putenv("APP_MODE=" . $input);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for $_GET -> putenv()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Laravel typed request accessors (SnkSQLQuery, SnkCommand) ---

func TestPHP_SQL_Sanitized_LaravelRequestInteger(t *testing.T) {
	code := `<?php
function getUser($request) {
    $id = $request->integer("user_id");
    $result = DB::select("SELECT * FROM users WHERE id = " . $id);
    return $result;
}
?>`
	flows := Analyze(code, "/app/UserController.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("$request->integer() should neutralize SQL taint flow")
	}
}

func TestPHP_Command_Sanitized_LaravelRequestBoolean(t *testing.T) {
	code := `<?php
function runTask($request) {
    $verbose = $request->boolean("verbose");
    exec("task run --verbose=" . $verbose);
}
?>`
	flows := Analyze(code, "/app/TaskController.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("$request->boolean() should neutralize command taint flow")
	}
}

// --- Laravel Str::slug sanitizer ---

func TestPHP_XSS_Sanitized_LaravelStrSlug(t *testing.T) {
	code := `<?php
use Illuminate\Support\Str;

function createPost($request) {
    $title = $request->input("title");
    $slug = Str::slug($title);
    echo "<a href='/posts/" . $slug . "'>" . $slug . "</a>";
}
?>`
	flows := Analyze(code, "/app/PostController.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Str::slug() should neutralize HTML output taint flow")
	}
}

func TestPHP_Command_Sanitized_LaravelStrSlug(t *testing.T) {
	code := `<?php
use Illuminate\Support\Str;

function generateFile($request) {
    $name = $request->input("filename");
    $safe = Str::slug($name);
    exec("convert " . $safe . ".jpg output.png");
}
?>`
	flows := Analyze(code, "/app/ImageController.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("Str::slug() should neutralize command taint flow")
	}
}
