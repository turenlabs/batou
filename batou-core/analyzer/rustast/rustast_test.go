package rustast

import (
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
	"strings"
	"testing"
)

func scanRust(t *testing.T, code string) []rules.Finding {
	t.Helper()
	tree := ast.Parse([]byte(code), rules.LangRust)
	ctx := &rules.ScanContext{
		FilePath: "/app/src/main.rs",
		Content:  code,
		Language: rules.LangRust,
		Tree:     tree,
	}
	a := &RustASTAnalyzer{}
	return a.Scan(ctx)
}

func TestUnsafeTransmute(t *testing.T) {
	code := `
fn convert(x: u32) -> f32 {
    unsafe {
        std::mem::transmute::<u32, f32>(x)
    }
}
`
	findings := scanRust(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-RUST-AST-001" && strings.Contains(f.Title, "transmute") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for transmute in unsafe block")
	}
}

// TestUnsafeTransmuteWithSafetyComment_Suppressed reproduces the
// tokio/cryptography/rocket FPs: an `unsafe { transmute(...) }` block
// preceded by a `// SAFETY: ...` comment must NOT produce BATOU-RUST-AST-001.
// Without the gate this rule fired on every transmute regardless of
// developer-authored justification.
func TestUnsafeTransmuteWithSafetyComment_Suppressed(t *testing.T) {
	cases := map[string]string{
		"canonical SAFETY uppercase": `
fn convert<'a>(slice: &[u8]) -> &'a [u8] {
    // SAFETY: caller guarantees slice outlives 'a.
    unsafe {
        std::mem::transmute::<&[u8], &'a [u8]>(slice)
    }
}
`,
		"multi-line SAFETY block": `
fn convert<'a>(slice: &[u8]) -> &'a [u8] {
    // SAFETY: This is necessary only due to a limitation in the
    // borrow checker. Once Rust starts using the polonius borrow
    // checker, this can be simplified.
    //
    // The safety of this transmute relies on the fact that the
    // value of the original buffer outlives the transmuted slice.
    unsafe {
        std::mem::transmute::<&[u8], &'a [u8]>(slice)
    }
}
`,
		"Safety mixed-case": `
fn convert<'a>(slice: &[u8]) -> &'a [u8] {
    // Safety: caller guarantees slice outlives 'a.
    unsafe { std::mem::transmute::<&[u8], &'a [u8]>(slice) }
}
`,
		"informal 'This is safe' comment (tokio mpsc.rs)": `
fn new<T>(v: InnerFuture<'_, T>) -> InnerFuture<'static, T> {
    // This is safe because make_acquire_future(None) is actually 'static
    unsafe { mem::transmute::<InnerFuture<'_, T>, InnerFuture<'static, T>>(v) }
}
`,
		"SAFETY inside the unsafe block": `
fn convert<'a>(slice: &[u8]) -> &'a [u8] {
    unsafe {
        // SAFETY: caller guarantees slice outlives 'a.
        std::mem::transmute::<&[u8], &'a [u8]>(slice)
    }
}
`,
	}
	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			findings := scanRust(t, code)
			for _, f := range findings {
				if f.RuleID == "BATOU-RUST-AST-001" && strings.Contains(f.Title, "transmute") {
					t.Errorf("expected SAFETY comment to suppress BATOU-RUST-AST-001, but got finding: %s (line %d)", f.Title, f.LineNumber)
				}
			}
		})
	}
}

// TestUnsafeTransmuteWithoutSafetyComment_StillFlags ensures the gate is not
// over-broad: a transmute with no SAFETY justification must still flag.
func TestUnsafeTransmuteWithoutSafetyComment_StillFlags(t *testing.T) {
	code := `
fn convert<'a>(slice: &[u8]) -> &'a [u8] {
    // Just a regular comment, not a justification.
    unsafe {
        std::mem::transmute::<&[u8], &'a [u8]>(slice)
    }
}
`
	findings := scanRust(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-RUST-AST-001" && strings.Contains(f.Title, "transmute") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected BATOU-RUST-AST-001 finding when no SAFETY comment is present")
	}
}

// TestUnsafeTransmute_RawPtrDerefStillFlagsWithSafety verifies the SAFETY
// gate only suppresses transmute findings — raw-pointer-deref findings on
// the same block are independent and should still fire.
func TestUnsafeTransmute_RawPtrDerefStillFlagsWithSafety(t *testing.T) {
	code := `
fn deref_raw(p: *const i32) -> i32 {
    // SAFETY: caller guarantees p is valid and aligned.
    unsafe {
        *p
    }
}
`
	findings := scanRust(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-RUST-AST-001" && strings.Contains(f.Title, "Raw pointer") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected raw-pointer-deref finding to still fire even with SAFETY comment (gate is transmute-only)")
	}
}

func TestUnsafeRawPointerDeref(t *testing.T) {
	code := `
fn deref_raw(p: *const i32) -> i32 {
    unsafe {
        *p
    }
}
`
	findings := scanRust(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-RUST-AST-001" && strings.Contains(f.Title, "Raw pointer") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for raw pointer dereference in unsafe block")
	}
}

func TestSafeCodeNoUnsafeFindings(t *testing.T) {
	code := `
fn add(a: i32, b: i32) -> i32 {
    a + b
}
`
	findings := scanRust(t, code)
	for _, f := range findings {
		if f.RuleID == "BATOU-RUST-AST-001" {
			t.Error("unexpected unsafe finding in safe code")
		}
	}
}

func TestFormatSQLInjection(t *testing.T) {
	code := `
fn get_user(id: &str) -> String {
    let query = format!("SELECT * FROM users WHERE id = {}", id);
    query
}
`
	findings := scanRust(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-RUST-AST-002" {
			found = true
			if f.Severity != rules.Critical {
				t.Errorf("expected Critical severity, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected SQL injection finding for format!()")
	}
}

func TestFormatNonSQL(t *testing.T) {
	code := `
fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}
`
	findings := scanRust(t, code)
	for _, f := range findings {
		if f.RuleID == "BATOU-RUST-AST-002" {
			t.Error("unexpected SQL injection finding for non-SQL format!()")
		}
	}
}

// TestFormatSQLKeywordSubstringFP guards the word-boundary fix: prose format!()
// strings whose words merely CONTAIN a SQL verb as a substring ("executable" →
// "exec", "created" → "create", "updated" → "update") must NOT fire RUST-AST-002.
// Reproduced from a real scan of ripgrep (decompress.rs) where the error message
// `format!("{}: could not find executable in PATH", prog.display())` was flagged
// CRITICAL "SQL injection".
func TestFormatSQLKeywordSubstringFP(t *testing.T) {
	cases := []string{
		`fn f(p: &str) -> String { format!("{}: could not find executable in PATH", p) }`,
		`fn f(n: &str) -> String { format!("created directory {}", n) }`,
		`fn f(n: &str) -> String { format!("updated {} records in cache", n) }`,
		`fn f(n: &str) -> String { format!("deleted temp file {}", n) }`,
		`fn f(n: &str) -> String { format!("selection contains {} items", n) }`,
	}
	for _, code := range cases {
		for _, f := range scanRust(t, "\n"+code+"\n") {
			if f.RuleID == "BATOU-RUST-AST-002" {
				t.Errorf("unexpected SQL injection finding for non-SQL prose: %q", code)
			}
		}
	}
}

// TestFormatSQLInjectionVariants confirms real query templates (verb + clause)
// still fire after the word-boundary tightening.
func TestFormatSQLInjectionVariants(t *testing.T) {
	cases := []string{
		`fn f(v: &str) -> String { format!("INSERT INTO users VALUES ('{}')", v) }`,
		`fn f(v: &str) -> String { format!("UPDATE users SET name = '{}'", v) }`,
		`fn f(v: &str) -> String { format!("DELETE FROM users WHERE id = {}", v) }`,
	}
	for _, code := range cases {
		found := false
		for _, f := range scanRust(t, "\n"+code+"\n") {
			if f.RuleID == "BATOU-RUST-AST-002" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected SQL injection finding for query template: %q", code)
		}
	}
}

func TestCommandInjectionShell(t *testing.T) {
	code := `
fn run_cmd(input: &str) {
    let cmd = std::process::Command::new("sh").arg("-c").arg(input).spawn();
}
`
	findings := scanRust(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-RUST-AST-003" && f.Severity == rules.Critical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected critical command injection finding for shell execution")
	}
}

func TestCommandInjectionVarArg(t *testing.T) {
	code := `
fn run_cmd(filename: &str) {
    let cmd = std::process::Command::new("ls").arg(filename).spawn();
}
`
	findings := scanRust(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-RUST-AST-003" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected command injection finding for variable argument")
	}
}

func TestSafeCommand(t *testing.T) {
	code := `
fn list_files() {
    let cmd = std::process::Command::new("ls").arg("-la").spawn();
}
`
	findings := scanRust(t, code)
	for _, f := range findings {
		if f.RuleID == "BATOU-RUST-AST-003" && f.Severity == rules.Critical {
			t.Error("unexpected critical finding for command with literal args")
		}
	}
}

func TestUnsafeUnwrapOnParse(t *testing.T) {
	code := `
fn parse_input(s: &str) -> i32 {
    s.parse::<i32>().unwrap()
}
`
	findings := scanRust(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-RUST-AST-004" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for .unwrap() on parse()")
	}
}

func TestSafeUnwrapOnVec(t *testing.T) {
	code := `
fn first() -> i32 {
    let v = vec![1, 2, 3];
    v.first().unwrap()
}
`
	findings := scanRust(t, code)
	for _, f := range findings {
		if f.RuleID == "BATOU-RUST-AST-004" {
			t.Error("unexpected finding for unwrap on non-network call")
		}
	}
}

// TestUnwrapOnFsCreateDirWithPathLiteral guards against the substring
// FP that scan_harness surfaced: a path literal containing "get"
// (e.g. "target/debug/deps") triggered the rule via strings.Contains,
// because "tar*get*" contains the I/O method token "get". The
// word-boundary regex must only match real method calls.
func TestUnwrapOnFsCreateDirWithPathLiteral(t *testing.T) {
	code := `
fn setup() {
    let dir = std::path::PathBuf::new();
    std::fs::create_dir_all(dir.join("target/debug/deps")).unwrap();
    std::fs::write(dir.join("target/debug/deps/Cargo.toml"), "[package]").unwrap();
}
`
	findings := scanRust(t, code)
	for _, f := range findings {
		if f.RuleID == "BATOU-RUST-AST-004" {
			t.Errorf("path literal containing 'get' inside string should not fire RUST-AST-004: %s line=%d",
				f.MatchedText, f.LineNumber)
		}
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/src/main.rs",
		Content:  "fn main() {}",
		Language: rules.LangRust,
		Tree:     nil,
	}
	a := &RustASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings with nil tree")
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/main.go",
		Content:  "package main",
		Language: rules.LangGo,
	}
	a := &RustASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestLineNumbers(t *testing.T) {
	code := `fn main() {
    unsafe {
        std::mem::transmute::<u32, f32>(0);
    }
}
`
	findings := scanRust(t, code)
	for _, f := range findings {
		if f.RuleID == "BATOU-RUST-AST-001" && f.LineNumber < 1 {
			t.Errorf("expected positive line number, got %d", f.LineNumber)
		}
	}
}
