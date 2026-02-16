package goast

import (
	"testing"

	"github.com/turenlabs/batou/internal/rules"
)

func scanGo(code string) []rules.Finding {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.go",
		Content:  code,
		Language: rules.LangGo,
	}
	a := &GoASTAnalyzer{}
	return a.Scan(ctx)
}

func findByRule(findings []rules.Finding, ruleID string) *rules.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

func countByRule(findings []rules.Finding, ruleID string) int {
	count := 0
	for _, f := range findings {
		if f.RuleID == ruleID {
			count++
		}
	}
	return count
}

// =========================================================================
// BATOU-AST-001: UnsafePackageUsage
// =========================================================================

func TestAST001_UnsafeImport(t *testing.T) {
	code := `package main

import "unsafe"

func main() {}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-001")
	if f == nil {
		t.Error("expected finding for unsafe import")
	}
}

func TestAST001_UnsafePointerUsage(t *testing.T) {
	code := `package main

import "unsafe"

func cast(p *int) {
	ptr := unsafe.Pointer(p)
	_ = ptr
}
`
	findings := scanGo(code)
	count := countByRule(findings, "BATOU-AST-001")
	if count < 2 {
		t.Errorf("expected at least 2 AST-001 findings (import + usage), got %d", count)
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestAST001_AliasedUnsafe(t *testing.T) {
	code := `package main

import u "unsafe"

func cast(p *int) {
	ptr := u.Pointer(p)
	_ = ptr
}
`
	findings := scanGo(code)
	count := countByRule(findings, "BATOU-AST-001")
	if count < 2 {
		t.Errorf("expected at least 2 AST-001 findings for aliased unsafe, got %d", count)
	}
}

func TestAST001_SafeNoUnsafe(t *testing.T) {
	code := `package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-001")
	if f != nil {
		t.Error("should not flag code without unsafe import")
	}
}

// =========================================================================
// BATOU-AST-002: SQLStringConcat
// =========================================================================

func TestAST002_QueryWithConcat(t *testing.T) {
	code := `package main

import "database/sql"

func getUser(db *sql.DB, name string) {
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-002")
	if f == nil {
		t.Error("expected finding for SQL string concatenation in db.Query")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestAST002_ExecWithSprintf(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"fmt"
)

func deleteUser(db *sql.DB, id string) {
	db.Exec(fmt.Sprintf("DELETE FROM users WHERE id = %s", id))
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-002")
	if f == nil {
		t.Error("expected finding for SQL fmt.Sprintf in db.Exec")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestAST002_QueryContextWithSprintf(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"
	"fmt"
)

func getUser(db *sql.DB, ctx context.Context, name string) {
	db.QueryContext(ctx, fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-002")
	if f == nil {
		t.Error("expected finding for SQL fmt.Sprintf in db.QueryContext")
	}
}

func TestAST002_SafeParameterized(t *testing.T) {
	code := `package main

import "database/sql"

func getUser(db *sql.DB, name string) {
	db.Query("SELECT * FROM users WHERE name = ?", name)
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-002")
	if f != nil {
		t.Error("should not flag parameterized query")
	}
}

func TestAST002_SafeLiteralConcat(t *testing.T) {
	code := `package main

import "database/sql"

func getUsers(db *sql.DB) {
	db.Query("SELECT * FROM users " + "WHERE active = true")
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-002")
	if f != nil {
		t.Error("should not flag literal-only string concatenation")
	}
}

// =========================================================================
// BATOU-AST-003: ExecCommandInjection
// =========================================================================

func TestAST003_ShellExec(t *testing.T) {
	code := `package main

import "os/exec"

func run(cmd string) {
	exec.Command("sh", "-c", cmd)
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-003")
	if f == nil {
		t.Error("expected finding for exec.Command shell injection")
	}
}

func TestAST003_BashExec(t *testing.T) {
	code := `package main

import "os/exec"

func run(cmd string) {
	exec.Command("/bin/bash", "-c", cmd)
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-003")
	if f == nil {
		t.Error("expected finding for exec.Command with /bin/bash")
	}
}

func TestAST003_VariableCommand(t *testing.T) {
	code := `package main

import "os/exec"

func run(program string) {
	exec.Command(program)
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-003")
	if f == nil {
		t.Error("expected finding for variable command name")
	}
}

func TestAST003_VariableArgs(t *testing.T) {
	code := `package main

import "os/exec"

func run(arg string) {
	exec.Command("ls", arg)
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-003")
	if f == nil {
		t.Error("expected finding for variable arguments to exec.Command")
	}
}

func TestAST003_SafeLiteralCommand(t *testing.T) {
	code := `package main

import "os/exec"

func run() {
	exec.Command("ls", "-la", "/tmp")
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-003")
	if f != nil {
		t.Error("should not flag exec.Command with all literal args")
	}
}

// =========================================================================
// BATOU-AST-004: UncheckedError
// =========================================================================

func TestAST004_BlankError(t *testing.T) {
	code := `package main

import "os"

func handler() {
	_, _ = os.Open("/etc/passwd")
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-004")
	if f == nil {
		t.Error("expected finding for unchecked error from os.Open")
	}
}

func TestAST004_DiscardedReturn(t *testing.T) {
	code := `package main

import "net/http"

func main() {
	http.ListenAndServe(":8080", nil)
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-004")
	if f == nil {
		t.Error("expected finding for discarded return from http.ListenAndServe")
	}
}

func TestAST004_SafeCheckedError(t *testing.T) {
	code := `package main

import "os"

func handler() error {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return err
	}
	_ = f
	return nil
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-004")
	if f != nil {
		t.Error("should not flag properly checked error")
	}
}

// =========================================================================
// BATOU-AST-005: DeprecatedCrypto
// =========================================================================

func TestAST005_CryptoDES(t *testing.T) {
	code := `package main

import "crypto/des"

func encrypt() {
	_ = des.NewCipher
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-005")
	if f == nil {
		t.Error("expected finding for crypto/des import")
	}
}

func TestAST005_CryptoRC4(t *testing.T) {
	code := `package main

import "crypto/rc4"

func encrypt() {
	_ = rc4.NewCipher
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-005")
	if f == nil {
		t.Error("expected finding for crypto/rc4 import")
	}
}

func TestAST005_CryptoMD5(t *testing.T) {
	code := `package main

import "crypto/md5"

func hash() {
	_ = md5.New()
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-005")
	if f == nil {
		t.Error("expected finding for crypto/md5 import")
	}
}

func TestAST005_CryptoSHA1(t *testing.T) {
	code := `package main

import "crypto/sha1"

func hash() {
	_ = sha1.New()
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-005")
	if f == nil {
		t.Error("expected finding for crypto/sha1 import")
	}
}

func TestAST005_MathRandWithoutCryptoRand(t *testing.T) {
	code := `package main

import "math/rand"

func token() int {
	return rand.Intn(1000)
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-005")
	if f == nil {
		t.Error("expected finding for math/rand without crypto/rand")
	}
}

func TestAST005_SafeMathRandWithCryptoRand(t *testing.T) {
	code := `package main

import (
	"crypto/rand"
	"math/rand"
)

func token() {
	_ = rand.Intn(1000)
	_ = rand.Reader
}
`
	findings := scanGo(code)
	// Should not flag math/rand when crypto/rand is also imported
	for _, f := range findings {
		if f.RuleID == "BATOU-AST-005" && f.Title == "Non-cryptographic random number generator without crypto/rand" {
			t.Error("should not flag math/rand when crypto/rand is also imported")
		}
	}
}

func TestAST005_SafeCryptoAES(t *testing.T) {
	code := `package main

import "crypto/aes"

func encrypt() {
	_ = aes.NewCipher
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-005")
	if f != nil {
		t.Error("should not flag crypto/aes")
	}
}

// =========================================================================
// BATOU-AST-006: HttpServerMisconfig
// =========================================================================

func TestAST006_ListenAndServeNoTLS(t *testing.T) {
	code := `package main

import "net/http"

func main() {
	http.ListenAndServe(":8080", nil)
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-006")
	if f == nil {
		t.Error("expected finding for http.ListenAndServe without TLS")
	}
}

func TestAST006_ServerMissingTimeouts(t *testing.T) {
	code := `package main

import "net/http"

func main() {
	srv := &http.Server{
		Addr: ":8080",
	}
	_ = srv
}
`
	findings := scanGo(code)
	count := countByRule(findings, "BATOU-AST-006")
	if count == 0 {
		t.Error("expected finding for http.Server missing timeouts")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestAST006_SafeServerWithTimeouts(t *testing.T) {
	code := `package main

import (
	"net/http"
	"time"
)

func main() {
	srv := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	_ = srv
}
`
	findings := scanGo(code)
	// Should not flag server with all timeouts set
	for _, f := range findings {
		if f.RuleID == "BATOU-AST-006" && f.Title == "HTTP server missing timeout configuration" {
			t.Error("should not flag http.Server with all timeouts configured")
		}
	}
}

func TestAST006_ServerWithReadHeaderTimeout(t *testing.T) {
	code := `package main

import (
	"net/http"
	"time"
)

func main() {
	srv := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	_ = srv
}
`
	findings := scanGo(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-AST-006" && f.Title == "HTTP server missing timeout configuration" {
			t.Error("should not flag server with ReadHeaderTimeout as alternative to ReadTimeout")
		}
	}
}

// =========================================================================
// BATOU-AST-007: DeferInLoop
// =========================================================================

func TestAST007_DeferInForLoop(t *testing.T) {
	code := `package main

import "os"

func processFiles(paths []string) {
	for i := 0; i < len(paths); i++ {
		f, _ := os.Open(paths[i])
		defer f.Close()
	}
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-007")
	if f == nil {
		t.Error("expected finding for defer inside for loop")
	}
}

func TestAST007_DeferInRangeLoop(t *testing.T) {
	code := `package main

import "os"

func processFiles(paths []string) {
	for _, path := range paths {
		f, _ := os.Open(path)
		defer f.Close()
	}
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-007")
	if f == nil {
		t.Error("expected finding for defer inside range loop")
	}
}

func TestAST007_DeferInLoopNestedIf(t *testing.T) {
	code := `package main

import "os"

func processFiles(paths []string) {
	for _, path := range paths {
		f, err := os.Open(path)
		if err == nil {
			defer f.Close()
		}
	}
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-007")
	if f == nil {
		t.Error("expected finding for defer inside if inside loop")
	}
}

func TestAST007_SafeDeferOutsideLoop(t *testing.T) {
	code := `package main

import "os"

func handler() {
	f, _ := os.Open("/tmp/file")
	defer f.Close()
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-007")
	if f != nil {
		t.Error("should not flag defer outside of loop")
	}
}

func TestAST007_SafeDeferInClosureInsideLoop(t *testing.T) {
	code := `package main

import "os"

func processFiles(paths []string) {
	for _, path := range paths {
		func() {
			f, _ := os.Open(path)
			defer f.Close()
		}()
	}
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-007")
	if f != nil {
		t.Error("should not flag defer inside closure within loop")
	}
}

// =========================================================================
// BATOU-AST-008: GoroutineLeak
// =========================================================================

func TestAST008_GoroutineNoContext(t *testing.T) {
	code := `package main

func handler() {
	go func() {
		doWork()
	}()
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-008")
	if f == nil {
		t.Error("expected finding for goroutine without context")
	}
}

func TestAST008_GoroutineCallNoContext(t *testing.T) {
	code := `package main

func handler() {
	go doWork()
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-008")
	if f == nil {
		t.Error("expected finding for go doWork() without context argument")
	}
}

func TestAST008_SafeGoroutineWithContextParam(t *testing.T) {
	code := `package main

import "context"

func handler(ctx context.Context) {
	go func(ctx context.Context) {
		doWork(ctx)
	}(ctx)
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-008")
	if f != nil {
		t.Error("should not flag goroutine with context.Context parameter")
	}
}

func TestAST008_SafeGoroutineWithCapturedCtx(t *testing.T) {
	code := `package main

import "context"

func handler() {
	ctx := context.Background()
	go func() {
		doWork(ctx)
	}()
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-008")
	if f != nil {
		t.Error("should not flag goroutine that captures ctx variable")
	}
}

func TestAST008_SafeGoroutineCallWithCtx(t *testing.T) {
	code := `package main

import "context"

func handler() {
	ctx := context.Background()
	go doWork(ctx)
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-008")
	if f != nil {
		t.Error("should not flag go doWork(ctx)")
	}
}

// =========================================================================
// Edge cases
// =========================================================================

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.py",
		Content:  `import unsafe`,
		Language: rules.LangPython,
	}
	a := &GoASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestParseError(t *testing.T) {
	code := `this is not valid go code {{{{`
	findings := scanGo(code)
	if len(findings) != 0 {
		t.Error("expected no findings for unparseable code")
	}
}

func TestEmptyFile(t *testing.T) {
	code := `package main`
	findings := scanGo(code)
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty file, got %d", len(findings))
	}
}
