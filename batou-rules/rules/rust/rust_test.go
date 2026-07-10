package rust

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// --- RS-002: Command Injection ---

func TestRS002_CommandNewShell(t *testing.T) {
	content := `use std::process::Command;
fn run(input: &str) {
    Command::new("sh").arg("-c").arg(input).output().unwrap();
}`
	result := testutil.ScanContent(t, "/app/exec.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-002")
}

func TestRS002_CommandNewFormat(t *testing.T) {
	content := `use std::process::Command;
fn run(program: &str) {
    Command::new(format!("/usr/bin/{}", program)).output().unwrap();
}`
	result := testutil.ScanContent(t, "/app/exec.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-002")
}

func TestRS002_CommandArgFormat(t *testing.T) {
	content := `use std::process::Command;
fn run(host: &str) {
    Command::new("ping").arg(format!("-c 3 {}", host)).output().unwrap();
}`
	result := testutil.ScanContent(t, "/app/exec.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-002")
}

func TestRS002_Safe_StaticCommand(t *testing.T) {
	content := `use std::process::Command;
fn run() {
    Command::new("ls").arg("-la").arg("/tmp").output().unwrap();
}`
	result := testutil.ScanContent(t, "/app/exec.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-002")
}

// --- RS-003: SQL Injection ---

func TestRS003_SQLFormat(t *testing.T) {
	content := `async fn get_user(pool: &PgPool, name: &str) {
    let query = format!("SELECT * FROM users WHERE name = '{}'", name);
    sqlx::query(&format!("SELECT * FROM users WHERE name = '{}'", name))
        .fetch_one(pool).await.unwrap();
}`
	result := testutil.ScanContent(t, "/app/db.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-003")
}

func TestRS003_DieselSQLFormat(t *testing.T) {
	content := `fn get_user(conn: &PgConnection, name: &str) {
    diesel::sql_query(format!("SELECT * FROM users WHERE name = '{}'", name))
        .load::<User>(conn).unwrap();
}`
	result := testutil.ScanContent(t, "/app/db.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-003")
}

func TestRS003_SQLVarFromFormat(t *testing.T) {
	content := `async fn get_user(pool: &PgPool, name: &str) {
    let query = format!("SELECT * FROM users WHERE name = '{}'", name);
    sqlx::query(&query).fetch_one(pool).await.unwrap();
}`
	result := testutil.ScanContent(t, "/app/db.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-003")
}

func TestRS003_Safe_Parameterized(t *testing.T) {
	content := `async fn get_user(pool: &PgPool, name: &str) {
    sqlx::query("SELECT * FROM users WHERE name = $1")
        .bind(name)
        .fetch_one(pool).await.unwrap();
}`
	result := testutil.ScanContent(t, "/app/db.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-003")
}

func TestRS003_Safe_QueryMacro(t *testing.T) {
	content := `async fn get_user(pool: &PgPool, name: &str) {
    sqlx::query!("SELECT * FROM users WHERE name = $1", name)
        .fetch_one(pool).await.unwrap();
}`
	result := testutil.ScanContent(t, "/app/db.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-003")
}

// --- RS-004: Path Traversal ---

func TestRS004_FsReadVariable(t *testing.T) {
	content := `fn read_file(filename: &str) -> String {
    std::fs::read_to_string(filename).unwrap()
}`
	result := testutil.ScanContent(t, "/app/files.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-004")
}

func TestRS004_Safe_WithCanonicalize(t *testing.T) {
	content := `fn read_file(filename: &str) -> String {
    let path = std::path::Path::new("/data").join(filename);
    let canonical = path.canonicalize().unwrap();
    if !canonical.starts_with("/data") {
        panic!("path traversal");
    }
    std::fs::read_to_string(canonical).unwrap()
}`
	result := testutil.ScanContent(t, "/app/files.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-004")
}

// --- RS-005: Insecure Deserialization ---

func TestRS005_BincodeDe(t *testing.T) {
	content := `fn process(data: &[u8]) {
    let msg: Message = bincode::deserialize(data).unwrap();
}`
	result := testutil.ScanContent(t, "/app/proto.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-005")
}

func TestRS005_RmpDe(t *testing.T) {
	content := `fn process(data: &[u8]) {
    let msg: Message = rmp_serde::from_slice(data).unwrap();
}`
	result := testutil.ScanContent(t, "/app/proto.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-005")
}

func TestRS005_Safe_JsonNoWebContext(t *testing.T) {
	content := `fn load_config() {
    let data = std::fs::read_to_string("config.json").unwrap();
    let config: Config = serde_json::from_str(&data).unwrap();
}`
	result := testutil.ScanContent(t, "/app/config.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-005")
}

// --- RS-006: Insecure TLS ---

func TestRS006_DangerAcceptInvalidCerts(t *testing.T) {
	content := `let client = reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .build().unwrap();`
	result := testutil.ScanContent(t, "/app/http.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-006")
}

func TestRS006_DangerAcceptInvalidHostnames(t *testing.T) {
	content := `let client = reqwest::Client::builder()
    .danger_accept_invalid_hostnames(true)
    .build().unwrap();`
	result := testutil.ScanContent(t, "/app/http.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-006")
}

func TestRS006_Safe_DefaultTLS(t *testing.T) {
	content := `let client = reqwest::Client::builder()
    .build().unwrap();`
	result := testutil.ScanContent(t, "/app/http.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-006")
}

// --- RS-007: Panic in Web Handler ---

func TestRS007_UnwrapInActixHandler(t *testing.T) {
	content := `async fn get_user(path: web::Path<String>, pool: web::Data<PgPool>) -> HttpResponse {
    let user_id = path.into_inner();
    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
        .fetch_one(pool.get_ref()).await.unwrap();
    HttpResponse::Ok().json(user)
}`
	result := testutil.ScanContent(t, "/app/handler.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-007")
}

func TestRS007_ExpectInHandler(t *testing.T) {
	content := `async fn process(body: web::Json<Request>) -> HttpResponse {
    let data = body.into_inner();
    let result = do_work(&data).expect("work failed");
    HttpResponse::Ok().json(result)
}`
	result := testutil.ScanContent(t, "/app/handler.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-007")
}

func TestRS007_Safe_QuestionMark(t *testing.T) {
	content := `fn not_a_handler() {
    let x = some_operation().unwrap();
}`
	result := testutil.ScanContent(t, "/app/util.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-007")
}

// --- RS-010: CORS Misconfiguration ---

func TestRS010_CorsPermissive(t *testing.T) {
	content := `use tower_http::cors::CorsLayer;
let cors = CorsLayer::permissive();`
	result := testutil.ScanContent(t, "/app/server.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-010")
}

func TestRS010_ActixCorsPermissive(t *testing.T) {
	content := `use actix_cors::Cors;
let cors = Cors::permissive();`
	result := testutil.ScanContent(t, "/app/server.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-010")
}

func TestRS010_AnyOriginWithCredentials(t *testing.T) {
	content := `use actix_cors::Cors;
let cors = Cors::default()
    .allow_any_origin()
    .allow_credentials(true);`
	result := testutil.ScanContent(t, "/app/server.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-010")
}

func TestRS010_Safe_SpecificOrigin(t *testing.T) {
	content := `use tower_http::cors::CorsLayer;
let cors = CorsLayer::new()
    .allow_origin(["https://example.com".parse().unwrap()]);`
	result := testutil.ScanContent(t, "/app/server.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-010")
}

// --- Fixture Tests ---

func TestFixture_Vulnerable(t *testing.T) {
	if !testutil.FixtureExists("rust/vulnerable/web_handler.rs") {
		t.Skip("Rust vulnerable fixture not available")
	}
	content := testutil.LoadFixture(t, "rust/vulnerable/web_handler.rs")
	result := testutil.ScanContent(t, "/app/handler.rs", content)
	testutil.AssertMinFindings(t, result, 1)
}

func TestFixture_Safe(t *testing.T) {
	if !testutil.FixtureExists("rust/safe/web_handler.rs") {
		t.Skip("Rust safe fixture not available")
	}
	content := testutil.LoadFixture(t, "rust/safe/web_handler.rs")
	result := testutil.ScanContent(t, "/app/handler.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-002")
	testutil.MustNotFindRule(t, result, "BATOU-RS-003")
}

// --- RS-019: Hard-coded cryptographic key (CWE-798) ---

func TestRS019_HardcodedAESKey(t *testing.T) {
	content := `use aes_gcm::{Aes256Gcm, KeyInit};
fn make_cipher() -> Aes256Gcm {
    Aes256Gcm::new_from_slice(b"0123456789abcdef0123456789abcdef").unwrap()
}`
	result := testutil.ScanContent(t, "/app/crypto.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-019")
}

func TestRS019_HardcodedChaChaKey(t *testing.T) {
	content := `use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
fn make_cipher() {
    let cipher = ChaCha20Poly1305::new_from_slice(&[0x00, 0x01, 0x02, 0x03]).unwrap();
}`
	result := testutil.ScanContent(t, "/app/crypto.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-019")
}

func TestRS019_Safe_CSPRNGKey(t *testing.T) {
	content := `use aes_gcm::{Aes256Gcm, KeyInit, aead::OsRng};
fn make_cipher() -> Aes256Gcm {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    Aes256Gcm::new(&key)
}`
	result := testutil.ScanContent(t, "/app/crypto.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-019")
}

func TestRS019_Safe_EnvKey(t *testing.T) {
	content := `use aes_gcm::{Aes256Gcm, KeyInit};
fn make_cipher() -> Aes256Gcm {
    let raw = std::env::var("AES_KEY").unwrap();
    Aes256Gcm::new_from_slice(raw.as_bytes()).unwrap()
}`
	result := testutil.ScanContent(t, "/app/crypto.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-019")
}

// --- RS-020: Session/auth cookie without Secure flag (CWE-614) ---

func TestRS020_SessionCookieNoSecure(t *testing.T) {
	content := `use actix_web::cookie::Cookie;
fn set_session(token: &str) -> Cookie {
    Cookie::build("session_id", token)
        .http_only(true)
        .finish()
}`
	result := testutil.ScanContent(t, "/app/auth.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-020")
}

func TestRS020_Safe_SecureSet(t *testing.T) {
	content := `use actix_web::cookie::Cookie;
fn set_session(token: &str) -> Cookie {
    Cookie::build("session_id", token)
        .secure(true)
        .http_only(true)
        .finish()
}`
	result := testutil.ScanContent(t, "/app/auth.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-020")
}

func TestRS020_Safe_NonAuthCookie(t *testing.T) {
	content := `use actix_web::cookie::Cookie;
fn set_pref(theme: &str) -> Cookie {
    Cookie::build("theme", theme)
        .http_only(true)
        .finish()
}`
	result := testutil.ScanContent(t, "/app/prefs.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-020")
}

func TestRS020_Safe_ExplicitSecureFalseDev(t *testing.T) {
	content := `use actix_web::cookie::Cookie;
fn set_session(token: &str) -> Cookie {
    Cookie::build("auth_token", token)
        .secure(false)
        .finish()
}`
	result := testutil.ScanContent(t, "/app/auth.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-020")
}
