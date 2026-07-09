package rust

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// scanRule runs a single rule directly against a constructed ScanContext.
// This exercises rules that are NOT registered in init() (RS-001, RS-008,
// RS-009, RS-011, RS-012, RS-014), which testutil.ScanContent cannot reach
// because it only runs rules.ForLanguage().
func scanRule(r rules.Rule, filePath, content string) []rules.Finding {
	ctx := &rules.ScanContext{
		FilePath: filePath,
		Content:  content,
		Language: rules.LangRust,
		IsNew:    true,
	}
	return r.Scan(ctx)
}

func hasRule(findings []rules.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Small helpers: truncate / isCommentLine
// ---------------------------------------------------------------------------

func TestTruncate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"short_untouched", "hello", 10, "hello"},
		{"trims_whitespace", "  hello  ", 10, "hello"},
		{"exact_length", "abcde", 5, "abcde"},
		{"over_length_truncated", "abcdefghij", 5, "abcde..."},
		{"empty", "   ", 5, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncate(tt.in, tt.max); got != tt.want {
				t.Fatalf("truncate(%q,%d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
		})
	}
}

func TestIsCommentLine(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"// a line comment", true},
		{"   // indented comment", true},
		{"/* block start", true},
		{" * continuation", true},
		{"let x = 5;", false},
		{"fn main() {}", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isCommentLine(tt.line); got != tt.want {
			t.Errorf("isCommentLine(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// RS-001: Unsafe Block Usage (unregistered — direct .Scan)
// ---------------------------------------------------------------------------

func TestRS001_UnsafeBlockDetected(t *testing.T) {
	content := `fn dangerous() {
    unsafe {
        let x = compute();
    }
}`
	findings := scanRule(UnsafeBlock{}, "/app/unsafe.rs", content)
	if !hasRule(findings, "BATOU-RS-001") {
		t.Fatalf("expected RS-001 unsafe block finding, got %d findings", len(findings))
	}
	if findings[0].Title != "Unsafe block detected" {
		t.Errorf("unexpected title: %q", findings[0].Title)
	}
}

func TestRS001_TransmuteInUnsafe(t *testing.T) {
	content := `fn convert(v: f64) -> u64 {
    unsafe {
        std::mem::transmute::<f64, u64>(v)
    }
}`
	findings := scanRule(UnsafeBlock{}, "/app/unsafe.rs", content)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-RS-001" && f.Severity == rules.High &&
			strings.Contains(f.Title, "transmute") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected High-severity transmute finding inside unsafe block, got %+v", findings)
	}
}

func TestRS001_FromRawPartsInUnsafe(t *testing.T) {
	content := `fn build(ptr: *const u8, len: usize) {
    unsafe {
        let s = std::slice::from_raw_parts(ptr, len);
    }
}`
	findings := scanRule(UnsafeBlock{}, "/app/unsafe.rs", content)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-RS-001" && strings.Contains(f.Title, "from_raw_parts") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected from_raw_parts finding inside unsafe block, got %+v", findings)
	}
}

func TestRS001_Safe_NoUnsafe(t *testing.T) {
	content := `fn safe_fn() {
    let x = 5 + 3;
    println!("{}", x);
}`
	findings := scanRule(UnsafeBlock{}, "/app/safe.rs", content)
	if hasRule(findings, "BATOU-RS-001") {
		t.Fatalf("did not expect RS-001 in safe code, got %+v", findings)
	}
}

func TestRS001_CommentLineSkipped(t *testing.T) {
	// An unsafe block that only appears inside a comment must not be flagged.
	content := `fn documented() {
    // unsafe { transmute(x) } -- this is just documentation
    let y = 1;
}`
	findings := scanRule(UnsafeBlock{}, "/app/doc.rs", content)
	if hasRule(findings, "BATOU-RS-001") {
		t.Fatalf("comment-only unsafe should be skipped, got %+v", findings)
	}
}

func TestRS001_Metadata(t *testing.T) {
	r := UnsafeBlock{}
	if r.ID() != "BATOU-RS-001" {
		t.Errorf("ID = %q", r.ID())
	}
	if r.Name() == "" || r.Description() == "" {
		t.Error("Name/Description should be non-empty")
	}
	if r.DefaultSeverity() != rules.Medium {
		t.Errorf("DefaultSeverity = %v, want Medium", r.DefaultSeverity())
	}
	if langs := r.Languages(); len(langs) != 1 || langs[0] != rules.LangRust {
		t.Errorf("Languages = %v", langs)
	}
}

// ---------------------------------------------------------------------------
// RS-008: Insecure Random (unregistered — direct .Scan)
// ---------------------------------------------------------------------------

func TestRS008_ThreadRngInSecurityContext(t *testing.T) {
	content := `use rand::Rng;
fn gen_token() -> u64 {
    let mut rng = rand::thread_rng();
    let token: u64 = rng.gen();
    token
}`
	findings := scanRule(InsecureRandom{}, "/app/token.rs", content)
	if !hasRule(findings, "BATOU-RS-008") {
		t.Fatalf("expected RS-008 in token-generation context, got %+v", findings)
	}
}

func TestRS008_RandRandomInSecurityContext(t *testing.T) {
	content := `fn make_secret() -> u128 {
    let secret: u128 = rand::random();
    secret
}`
	findings := scanRule(InsecureRandom{}, "/app/secret.rs", content)
	if !hasRule(findings, "BATOU-RS-008") {
		t.Fatalf("expected RS-008 for rand::random in secret context, got %+v", findings)
	}
}

func TestRS008_Safe_NoSecurityContext(t *testing.T) {
	// thread_rng used but no security-sensitive keyword in the file → no finding.
	content := `fn pick_color() -> u8 {
    let mut rng = rand::thread_rng();
    rng.gen_range(0..255)
}`
	findings := scanRule(InsecureRandom{}, "/app/color.rs", content)
	if hasRule(findings, "BATOU-RS-008") {
		t.Fatalf("did not expect RS-008 with no security context, got %+v", findings)
	}
}

func TestRS008_Safe_OsRngUsed(t *testing.T) {
	// OsRng present → file already uses a CSPRNG, rule bails.
	content := `use rand::rngs::OsRng;
fn gen_token() -> u64 {
    let mut rng = rand::thread_rng();
    let token: u64 = OsRng.gen();
    token
}`
	findings := scanRule(InsecureRandom{}, "/app/token.rs", content)
	if hasRule(findings, "BATOU-RS-008") {
		t.Fatalf("did not expect RS-008 when OsRng is used, got %+v", findings)
	}
}

func TestRS008_Metadata(t *testing.T) {
	r := InsecureRandom{}
	if r.ID() != "BATOU-RS-008" {
		t.Errorf("ID = %q", r.ID())
	}
	if r.DefaultSeverity() != rules.Medium {
		t.Errorf("DefaultSeverity = %v", r.DefaultSeverity())
	}
	if r.Name() == "" || r.Description() == "" {
		t.Error("Name/Description empty")
	}
}

// ---------------------------------------------------------------------------
// RS-009: Memory Unsafety Patterns (unregistered — direct .Scan)
// ---------------------------------------------------------------------------

func TestRS009_MemoryPatterns(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantCWE  string
		wantWord string
	}{
		{"transmute", `let x = std::mem::transmute::<f64, u64>(v);`, "CWE-704", "transmute"},
		{"from_raw_parts", `let s = slice::from_raw_parts(ptr, len);`, "CWE-119", "from_raw_parts"},
		{"mem_forget", `std::mem::forget(resource);`, "CWE-401", "forget"},
		{"box_from_raw", `let b = Box::from_raw(ptr);`, "CWE-415", "from_raw"},
		{"ptr_write", `std::ptr::write(dst, value);`, "CWE-119", "pointer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := "fn f() {\n    " + tt.line + "\n}"
			findings := scanRule(MemoryUnsafety{}, "/app/mem.rs", content)
			var got *rules.Finding
			for i := range findings {
				if findings[i].RuleID == "BATOU-RS-009" {
					got = &findings[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("expected RS-009 for %q, got %+v", tt.line, findings)
			}
			if got.CWEID != tt.wantCWE {
				t.Errorf("CWE = %q, want %q (title %q)", got.CWEID, tt.wantCWE, got.Title)
			}
		})
	}
}

func TestRS009_OneFindingPerLine(t *testing.T) {
	// A line that matches multiple patterns must yield exactly one finding
	// (the loop breaks after the first match).
	content := `fn f() {
    let x = std::mem::transmute(slice::from_raw_parts(ptr, len));
}`
	findings := scanRule(MemoryUnsafety{}, "/app/mem.rs", content)
	count := 0
	for _, f := range findings {
		if f.RuleID == "BATOU-RS-009" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 RS-009 finding per line, got %d", count)
	}
}

func TestRS009_Safe_NoUnsafeOps(t *testing.T) {
	content := `fn safe() {
    let v: Vec<u8> = Vec::new();
    let copy = v.clone();
}`
	findings := scanRule(MemoryUnsafety{}, "/app/safe.rs", content)
	if hasRule(findings, "BATOU-RS-009") {
		t.Fatalf("did not expect RS-009 in safe code, got %+v", findings)
	}
}

func TestRS009_Metadata(t *testing.T) {
	r := MemoryUnsafety{}
	if r.ID() != "BATOU-RS-009" || r.DefaultSeverity() != rules.High {
		t.Errorf("ID=%q sev=%v", r.ID(), r.DefaultSeverity())
	}
	if r.Name() == "" || r.Description() == "" {
		t.Error("Name/Description empty")
	}
}

// ---------------------------------------------------------------------------
// RS-011: Unsafe pointer deref (unregistered — direct .Scan)
// ---------------------------------------------------------------------------

func TestRS011_PtrOffsetInUnsafe(t *testing.T) {
	content := `fn read(ptr: *const u8) -> u8 {
    unsafe {
        let p = ptr.offset(2);
        *p
    }
}`
	findings := scanRule(RustUnsafePtrDeref{}, "/app/ptr.rs", content)
	if !hasRule(findings, "BATOU-RS-011") {
		t.Fatalf("expected RS-011 for ptr.offset in unsafe block, got %+v", findings)
	}
}

func TestRS011_RawDerefInUnsafe(t *testing.T) {
	content := `fn deref(ptr: *const Foo) {
    unsafe {
        let v = *ptr.field;
    }
}`
	findings := scanRule(RustUnsafePtrDeref{}, "/app/ptr.rs", content)
	if !hasRule(findings, "BATOU-RS-011") {
		t.Fatalf("expected RS-011 for raw deref in unsafe block, got %+v", findings)
	}
}

func TestRS011_Safe_NoUnsafeBlock(t *testing.T) {
	// .offset / deref outside an unsafe block are not flagged by this rule.
	content := `fn calc(ptr: *const u8) {
    let p = ptr.offset(1);
}`
	findings := scanRule(RustUnsafePtrDeref{}, "/app/ptr.rs", content)
	if hasRule(findings, "BATOU-RS-011") {
		t.Fatalf("did not expect RS-011 outside unsafe block, got %+v", findings)
	}
}

func TestRS011_Metadata(t *testing.T) {
	r := RustUnsafePtrDeref{}
	if r.ID() != "BATOU-RS-011" || r.DefaultSeverity() != rules.High {
		t.Errorf("ID=%q sev=%v", r.ID(), r.DefaultSeverity())
	}
	if r.Name() == "" || r.Description() == "" {
		t.Error("Name/Description empty")
	}
}

// ---------------------------------------------------------------------------
// RS-012: SQL injection via format! (unregistered — direct .Scan)
// ---------------------------------------------------------------------------

func TestRS012_QueryWithFormat(t *testing.T) {
	content := `fn lookup(name: &str) {
    let rows = conn.query(&format!("SELECT * FROM t WHERE n = '{}'", name));
}`
	findings := scanRule(RustSQLFormat{}, "/app/db.rs", content)
	if !hasRule(findings, "BATOU-RS-012") {
		t.Fatalf("expected RS-012 for query(format!), got %+v", findings)
	}
}

func TestRS012_FormatWithSQLKeyword(t *testing.T) {
	content := `fn build(id: u64) -> String {
    format!("DELETE FROM users WHERE id = {}", id)
}`
	findings := scanRule(RustSQLFormat{}, "/app/db.rs", content)
	if !hasRule(findings, "BATOU-RS-012") {
		t.Fatalf("expected RS-012 for format! with SQL keyword, got %+v", findings)
	}
}

func TestRS012_Safe_NoSQL(t *testing.T) {
	content := `fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}`
	findings := scanRule(RustSQLFormat{}, "/app/greet.rs", content)
	if hasRule(findings, "BATOU-RS-012") {
		t.Fatalf("did not expect RS-012 for non-SQL format!, got %+v", findings)
	}
}

func TestRS012_Metadata(t *testing.T) {
	r := RustSQLFormat{}
	if r.ID() != "BATOU-RS-012" || r.DefaultSeverity() != rules.High {
		t.Errorf("ID=%q sev=%v", r.ID(), r.DefaultSeverity())
	}
	if r.Name() == "" || r.Description() == "" {
		t.Error("Name/Description empty")
	}
}

// ---------------------------------------------------------------------------
// RS-014: unwrap() in production code (unregistered — direct .Scan)
// ---------------------------------------------------------------------------

func TestRS014_UnwrapInProd(t *testing.T) {
	content := `fn load() -> Config {
    let raw = std::fs::read_to_string("config.toml").unwrap();
    parse(&raw)
}`
	findings := scanRule(RustUnwrapProd{}, "/app/config.rs", content)
	if !hasRule(findings, "BATOU-RS-014") {
		t.Fatalf("expected RS-014 for unwrap in prod code, got %+v", findings)
	}
}

func TestRS014_Safe_TestFilePath(t *testing.T) {
	// The rule bails out for _test paths.
	content := `fn t() {
    let x = compute().unwrap();
}`
	findings := scanRule(RustUnwrapProd{}, "/app/config_test.rs", content)
	if hasRule(findings, "BATOU-RS-014") {
		t.Fatalf("did not expect RS-014 in _test file, got %+v", findings)
	}
}

func TestRS014_Safe_TestsModuleSkipped(t *testing.T) {
	// unwrap inside a #[cfg(test)] mod tests block is skipped.
	content := `fn prod() -> i32 { 1 }

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let x = compute().unwrap();
    }
}`
	findings := scanRule(RustUnwrapProd{}, "/app/lib.rs", content)
	if hasRule(findings, "BATOU-RS-014") {
		t.Fatalf("did not expect RS-014 inside #[cfg(test)] mod, got %+v", findings)
	}
}

func TestRS014_Metadata(t *testing.T) {
	r := RustUnwrapProd{}
	if r.ID() != "BATOU-RS-014" || r.DefaultSeverity() != rules.Medium {
		t.Errorf("ID=%q sev=%v", r.ID(), r.DefaultSeverity())
	}
	if r.Name() == "" || r.Description() == "" {
		t.Error("Name/Description empty")
	}
}

// ---------------------------------------------------------------------------
// RS-013: Command with user input (registered) — branches not yet covered
// ---------------------------------------------------------------------------

func TestRS013_ShellWithUserArg(t *testing.T) {
	content := `fn run(input: &str) {
    Command::new("sh").arg("-c").arg(input).output();
}`
	result := testutil.ScanContent(t, "/app/exec.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-013")
}

func TestRS013_CommandNewVariable(t *testing.T) {
	content := `fn run(prog: &str) {
    Command::new(prog).output();
}`
	result := testutil.ScanContent(t, "/app/exec.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-013")
}

func TestRS013_ArgFormat(t *testing.T) {
	content := `fn run(p: &str) {
    Command::new("git").arg(format!("--path={}", p)).output();
}`
	result := testutil.ScanContent(t, "/app/exec.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-013")
}

func TestRS013_Safe_StaticAll(t *testing.T) {
	content := `fn run() {
    Command::new("git").arg("status").output();
}`
	result := testutil.ScanContent(t, "/app/exec.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-013")
}

// ---------------------------------------------------------------------------
// RS-015: transmute (registered) — each variant branch
// ---------------------------------------------------------------------------

func TestRS015_ExplicitTypeParams(t *testing.T) {
	content := `fn convert(v: f64) -> u64 {
    unsafe { transmute::<f64, u64>(v) }
}`
	result := testutil.ScanContent(t, "/app/conv.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-015")
}

func TestRS015_TransmuteCopy(t *testing.T) {
	content := `fn copy_bits(v: &Foo) -> Bar {
    unsafe { transmute_copy(v) }
}`
	result := testutil.ScanContent(t, "/app/conv.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-015")
}

func TestRS015_GenericTransmute(t *testing.T) {
	content := `fn convert(v: A) -> B {
    unsafe { std::mem::transmute(v) }
}`
	result := testutil.ScanContent(t, "/app/conv.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-015")
}

func TestRS015_Safe_NoTransmute(t *testing.T) {
	content := `fn convert(v: i32) -> i64 {
    v as i64
}`
	result := testutil.ScanContent(t, "/app/conv.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-015")
}

// ---------------------------------------------------------------------------
// RS-016: Regex without size limit (registered)
// ---------------------------------------------------------------------------

func TestRS016_RegexNewVariable(t *testing.T) {
	content := `fn compile(pattern: &str) {
    let re = Regex::new(&pattern).unwrap();
}`
	result := testutil.ScanContent(t, "/app/re.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-016")
}

func TestRS016_RegexSetNew(t *testing.T) {
	content := `fn compile(patterns: Vec<String>) {
    let set = RegexSet::new(&patterns).unwrap();
}`
	result := testutil.ScanContent(t, "/app/re.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-016")
}

func TestRS016_Safe_SizeLimitConfigured(t *testing.T) {
	// A size_limit anywhere in the file suppresses the rule.
	content := `fn compile(pattern: &str) {
    let re = RegexBuilder::new(&pattern)
        .size_limit(1_000_000)
        .build()
        .unwrap();
}`
	result := testutil.ScanContent(t, "/app/re.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-016")
}

// ---------------------------------------------------------------------------
// RS-017: Web server without TLS (registered)
// ---------------------------------------------------------------------------

func TestRS017_ActixBindNoTLS(t *testing.T) {
	content := `fn main() {
    HttpServer::new(|| App::new()).bind("127.0.0.1:8080").run();
}`
	result := testutil.ScanContent(t, "/app/main.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-017")
}

func TestRS017_AxumBindNoTLS(t *testing.T) {
	content := `async fn main() {
    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
}`
	result := testutil.ScanContent(t, "/app/main.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-017")
}

func TestRS017_Safe_TLSConfigured(t *testing.T) {
	// bind_rustls present anywhere → TLS configured → rule bails.
	content := `fn main() {
    HttpServer::new(|| App::new())
        .bind_rustls("127.0.0.1:8443", config)
        .run();
}`
	result := testutil.ScanContent(t, "/app/main.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-017")
}

// ---------------------------------------------------------------------------
// RS-018: FFI without bounds checking (registered)
// ---------------------------------------------------------------------------

func TestRS018_ExternFnRawPtr(t *testing.T) {
	content := `#[no_mangle]
pub unsafe extern "C" fn process(data: *mut u8, len: usize) -> i32 {
    0
}`
	result := testutil.ScanContent(t, "/app/ffi.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-018")
}

func TestRS018_CStrFromPtr(t *testing.T) {
	content := `extern "C" {
    fn external(p: *const u8);
}
fn convert(ptr: *const i8) {
    let s = unsafe { CStr::from_ptr(ptr) };
}`
	result := testutil.ScanContent(t, "/app/ffi.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-018")
}

func TestRS018_Safe_NoFFI(t *testing.T) {
	// No extern "C" anywhere → rule bails before any per-line work.
	content := `fn convert(ptr: *const i8) {
    let s = unsafe { CStr::from_ptr(ptr) };
}`
	result := testutil.ScanContent(t, "/app/local.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-018")
}

// ---------------------------------------------------------------------------
// RS-004: Path traversal — file_name() guard branch (registered)
// ---------------------------------------------------------------------------

func TestRS004_Safe_FileNameGuard(t *testing.T) {
	// hasFileName guard suppresses the finding.
	content := `fn read_upload(name: &str) -> String {
    let safe = std::path::Path::new(name).file_name().unwrap();
    std::fs::read_to_string(safe).unwrap()
}`
	result := testutil.ScanContent(t, "/app/files.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-004")
}

func TestRS004_TokioFs(t *testing.T) {
	content := `async fn read_file(filename: &str) -> String {
    tokio::fs::read_to_string(filename).await.unwrap()
}`
	result := testutil.ScanContent(t, "/app/files.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-004")
}

// ---------------------------------------------------------------------------
// RS-005: Deserialization — ciborium + JSON-in-web-context branches
// ---------------------------------------------------------------------------

func TestRS005_CiboriumDe(t *testing.T) {
	content := `fn process(reader: impl Read) {
    let msg: Message = ciborium::from_reader(reader).unwrap();
}`
	result := testutil.ScanContent(t, "/app/proto.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-005")
}

func TestRS005_JsonInWebContext(t *testing.T) {
	content := `async fn handle(req: HttpRequest, body: web::Json<Raw>) {
    let parsed: Data = serde_json::from_str(&body.payload).unwrap();
}`
	result := testutil.ScanContent(t, "/app/handler.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-005")
}

// ---------------------------------------------------------------------------
// RS-010: CORS — any-origin-with-credentials High branch + non-cred safe
// ---------------------------------------------------------------------------

func TestRS010_CorsAnyOriginValueWithCredentials(t *testing.T) {
	content := `let cors = CorsLayer::new()
    .allow_origin(Any)
    .allow_credentials(true);`
	result := testutil.ScanContent(t, "/app/server.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-010")
}

func TestRS010_Safe_AnyOriginNoCredentials(t *testing.T) {
	// allow_any_origin without allow_credentials(true) nearby → not flagged
	// by the credentials branch.
	content := `let cors = Cors::default()
    .allow_any_origin()
    .max_age(3600);`
	result := testutil.ScanContent(t, "/app/server.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-010")
}

// ---------------------------------------------------------------------------
// RS-019 / RS-020: additional branch coverage
// ---------------------------------------------------------------------------

func TestRS019_KeyFromSliceLiteral(t *testing.T) {
	content := `use aes_gcm::Key;
fn k() {
    let key = Key::from_slice(b"0123456789abcdef0123456789abcdef");
}`
	result := testutil.ScanContent(t, "/app/crypto.rs", content)
	testutil.MustFindRule(t, result, "BATOU-RS-019")
}

func TestRS020_Safe_NoCookieBuilder(t *testing.T) {
	// No Cookie::build in the file → rule bails immediately.
	content := `fn handler() {
    let x = 5;
}`
	result := testutil.ScanContent(t, "/app/h.rs", content)
	testutil.MustNotFindRule(t, result, "BATOU-RS-020")
}
