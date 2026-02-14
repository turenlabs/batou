package rust

import (
	"testing"

	"github.com/turenio/gtss/internal/testutil"
)

// --- RS-001: Unsafe Block Usage ---

func TestRS001_UnsafeBlock(t *testing.T) {
	content := `fn dangerous() {
    unsafe {
        let ptr = &mut x as *mut i32;
        *ptr = 42;
    }
}`
	result := testutil.ScanContent(t, "/app/handler.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-001")
}

func TestRS001_UnsafeTransmute(t *testing.T) {
	content := `fn convert() {
    unsafe {
        let val: u64 = std::mem::transmute(some_f64);
    }
}`
	result := testutil.ScanContent(t, "/app/convert.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-001")
}

func TestRS001_Safe_NoUnsafe(t *testing.T) {
	content := `fn safe_function() {
    let x = 42;
    let y = x + 1;
    println!("{}", y);
}`
	result := testutil.ScanContent(t, "/app/safe.rs", content)
	testutil.MustNotFindRule(t, result, "GTSS-RS-001")
}

// --- RS-002: Command Injection ---

func TestRS002_CommandNewShell(t *testing.T) {
	content := `use std::process::Command;
fn run(input: &str) {
    Command::new("sh").arg("-c").arg(input).output().unwrap();
}`
	result := testutil.ScanContent(t, "/app/exec.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-002")
}

func TestRS002_CommandNewFormat(t *testing.T) {
	content := `use std::process::Command;
fn run(program: &str) {
    Command::new(format!("/usr/bin/{}", program)).output().unwrap();
}`
	result := testutil.ScanContent(t, "/app/exec.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-002")
}

func TestRS002_CommandArgFormat(t *testing.T) {
	content := `use std::process::Command;
fn run(host: &str) {
    Command::new("ping").arg(format!("-c 3 {}", host)).output().unwrap();
}`
	result := testutil.ScanContent(t, "/app/exec.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-002")
}

func TestRS002_Safe_StaticCommand(t *testing.T) {
	content := `use std::process::Command;
fn run() {
    Command::new("ls").arg("-la").arg("/tmp").output().unwrap();
}`
	result := testutil.ScanContent(t, "/app/exec.rs", content)
	testutil.MustNotFindRule(t, result, "GTSS-RS-002")
}

// --- RS-003: SQL Injection ---

func TestRS003_SQLFormat(t *testing.T) {
	content := `async fn get_user(pool: &PgPool, name: &str) {
    let query = format!("SELECT * FROM users WHERE name = '{}'", name);
    sqlx::query(&format!("SELECT * FROM users WHERE name = '{}'", name))
        .fetch_one(pool).await.unwrap();
}`
	result := testutil.ScanContent(t, "/app/db.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-003")
}

func TestRS003_DieselSQLFormat(t *testing.T) {
	content := `fn get_user(conn: &PgConnection, name: &str) {
    diesel::sql_query(format!("SELECT * FROM users WHERE name = '{}'", name))
        .load::<User>(conn).unwrap();
}`
	result := testutil.ScanContent(t, "/app/db.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-003")
}

func TestRS003_SQLVarFromFormat(t *testing.T) {
	content := `async fn get_user(pool: &PgPool, name: &str) {
    let query = format!("SELECT * FROM users WHERE name = '{}'", name);
    sqlx::query(&query).fetch_one(pool).await.unwrap();
}`
	result := testutil.ScanContent(t, "/app/db.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-003")
}

func TestRS003_Safe_Parameterized(t *testing.T) {
	content := `async fn get_user(pool: &PgPool, name: &str) {
    sqlx::query("SELECT * FROM users WHERE name = $1")
        .bind(name)
        .fetch_one(pool).await.unwrap();
}`
	result := testutil.ScanContent(t, "/app/db.rs", content)
	testutil.MustNotFindRule(t, result, "GTSS-RS-003")
}

func TestRS003_Safe_QueryMacro(t *testing.T) {
	content := `async fn get_user(pool: &PgPool, name: &str) {
    sqlx::query!("SELECT * FROM users WHERE name = $1", name)
        .fetch_one(pool).await.unwrap();
}`
	result := testutil.ScanContent(t, "/app/db.rs", content)
	testutil.MustNotFindRule(t, result, "GTSS-RS-003")
}

// --- RS-004: Path Traversal ---

func TestRS004_FsReadVariable(t *testing.T) {
	content := `fn read_file(filename: &str) -> String {
    std::fs::read_to_string(filename).unwrap()
}`
	result := testutil.ScanContent(t, "/app/files.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-004")
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
	testutil.MustNotFindRule(t, result, "GTSS-RS-004")
}

// --- RS-005: Insecure Deserialization ---

func TestRS005_BincodeDe(t *testing.T) {
	content := `fn process(data: &[u8]) {
    let msg: Message = bincode::deserialize(data).unwrap();
}`
	result := testutil.ScanContent(t, "/app/proto.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-005")
}

func TestRS005_RmpDe(t *testing.T) {
	content := `fn process(data: &[u8]) {
    let msg: Message = rmp_serde::from_slice(data).unwrap();
}`
	result := testutil.ScanContent(t, "/app/proto.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-005")
}

func TestRS005_Safe_JsonNoWebContext(t *testing.T) {
	content := `fn load_config() {
    let data = std::fs::read_to_string("config.json").unwrap();
    let config: Config = serde_json::from_str(&data).unwrap();
}`
	result := testutil.ScanContent(t, "/app/config.rs", content)
	testutil.MustNotFindRule(t, result, "GTSS-RS-005")
}

// --- RS-006: Insecure TLS ---

func TestRS006_DangerAcceptInvalidCerts(t *testing.T) {
	content := `let client = reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .build().unwrap();`
	result := testutil.ScanContent(t, "/app/http.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-006")
}

func TestRS006_DangerAcceptInvalidHostnames(t *testing.T) {
	content := `let client = reqwest::Client::builder()
    .danger_accept_invalid_hostnames(true)
    .build().unwrap();`
	result := testutil.ScanContent(t, "/app/http.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-006")
}

func TestRS006_Safe_DefaultTLS(t *testing.T) {
	content := `let client = reqwest::Client::builder()
    .build().unwrap();`
	result := testutil.ScanContent(t, "/app/http.rs", content)
	testutil.MustNotFindRule(t, result, "GTSS-RS-006")
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
	testutil.MustFindRule(t, result, "GTSS-RS-007")
}

func TestRS007_ExpectInHandler(t *testing.T) {
	content := `async fn process(body: web::Json<Request>) -> HttpResponse {
    let data = body.into_inner();
    let result = do_work(&data).expect("work failed");
    HttpResponse::Ok().json(result)
}`
	result := testutil.ScanContent(t, "/app/handler.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-007")
}

func TestRS007_Safe_QuestionMark(t *testing.T) {
	content := `fn not_a_handler() {
    let x = some_operation().unwrap();
}`
	result := testutil.ScanContent(t, "/app/util.rs", content)
	testutil.MustNotFindRule(t, result, "GTSS-RS-007")
}

// --- RS-008: Insecure Random ---

func TestRS008_ThreadRngForToken(t *testing.T) {
	content := `use rand::Rng;
fn generate_token() -> String {
    let mut rng = thread_rng();
    let token: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    hex::encode(token)
}`
	result := testutil.ScanContent(t, "/app/auth.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-008")
}

func TestRS008_Safe_OsRng(t *testing.T) {
	content := `use rand::rngs::OsRng;
use rand::Rng;
fn generate_token() -> String {
    let token: Vec<u8> = (0..32).map(|_| OsRng.gen()).collect();
    hex::encode(token)
}`
	result := testutil.ScanContent(t, "/app/auth.rs", content)
	testutil.MustNotFindRule(t, result, "GTSS-RS-008")
}

func TestRS008_Safe_NonSecurityContext(t *testing.T) {
	content := `use rand::Rng;
fn shuffle_items(items: &mut Vec<i32>) {
    let mut rng = thread_rng();
    items.shuffle(&mut rng);
}`
	result := testutil.ScanContent(t, "/app/game.rs", content)
	testutil.MustNotFindRule(t, result, "GTSS-RS-008")
}

// --- RS-009: Memory Unsafety Patterns ---

func TestRS009_Transmute(t *testing.T) {
	content := `fn convert(val: f64) -> u64 {
    unsafe { std::mem::transmute(val) }
}`
	result := testutil.ScanContent(t, "/app/convert.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-009")
}

func TestRS009_FromRawParts(t *testing.T) {
	content := `fn make_slice(ptr: *const u8, len: usize) -> &'static [u8] {
    unsafe { std::slice::from_raw_parts(ptr, len) }
}`
	result := testutil.ScanContent(t, "/app/ffi.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-009")
}

func TestRS009_MemForget(t *testing.T) {
	content := `fn leak_resource(resource: Resource) {
    std::mem::forget(resource);
}`
	result := testutil.ScanContent(t, "/app/resource.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-009")
}

func TestRS009_BoxFromRaw(t *testing.T) {
	content := `fn reclaim(ptr: *mut Widget) {
    let widget = unsafe { Box::from_raw(ptr) };
}`
	result := testutil.ScanContent(t, "/app/ffi.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-009")
}

func TestRS009_Safe_NoUnsafePatterns(t *testing.T) {
	content := `fn safe_vec() {
    let v = vec![1, 2, 3];
    let s = &v[..];
    println!("{:?}", s);
}`
	result := testutil.ScanContent(t, "/app/safe.rs", content)
	testutil.MustNotFindRule(t, result, "GTSS-RS-009")
}

// --- RS-010: CORS Misconfiguration ---

func TestRS010_CorsPermissive(t *testing.T) {
	content := `use tower_http::cors::CorsLayer;
let cors = CorsLayer::permissive();`
	result := testutil.ScanContent(t, "/app/server.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-010")
}

func TestRS010_ActixCorsPermissive(t *testing.T) {
	content := `use actix_cors::Cors;
let cors = Cors::permissive();`
	result := testutil.ScanContent(t, "/app/server.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-010")
}

func TestRS010_AnyOriginWithCredentials(t *testing.T) {
	content := `use actix_cors::Cors;
let cors = Cors::default()
    .allow_any_origin()
    .allow_credentials(true);`
	result := testutil.ScanContent(t, "/app/server.rs", content)
	testutil.MustFindRule(t, result, "GTSS-RS-010")
}

func TestRS010_Safe_SpecificOrigin(t *testing.T) {
	content := `use tower_http::cors::CorsLayer;
let cors = CorsLayer::new()
    .allow_origin(["https://example.com".parse().unwrap()]);`
	result := testutil.ScanContent(t, "/app/server.rs", content)
	testutil.MustNotFindRule(t, result, "GTSS-RS-010")
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
	testutil.MustNotFindRule(t, result, "GTSS-RS-002")
	testutil.MustNotFindRule(t, result, "GTSS-RS-003")
}
