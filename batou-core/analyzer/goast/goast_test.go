package goast

import (
	"github.com/turenlabs/batou-rules/rules"
	"testing"
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

// TestAST006_PartialTimeout_ReadHeaderOnly is the real-world FP regression test.
// Grafana's pkg/server/instrumentation_service.go sets ReadHeaderTimeout (the
// Go-documented Slowloris defense) but deliberately omits WriteTimeout and
// IdleTimeout. The old rule demanded all three and flagged this well-defended
// server. A request-phase timeout is present, so the CWE-400 threat is bounded
// and the finding must NOT fire.
func TestAST006_PartialTimeout_ReadHeaderOnly_NoFinding(t *testing.T) {
	code := `package main

import (
	"net/http"
	"time"
)

func newServer(router http.Handler) *http.Server {
	return &http.Server{
		// 5s timeout for header reads to avoid Slowloris attacks
		ReadHeaderTimeout: 5 * time.Second,
		Addr:              ":8080",
		Handler:           router,
	}
}
`
	findings := scanGo(code)
	if f := findByRule(findings, "BATOU-AST-006"); f != nil {
		t.Errorf("FP: server with ReadHeaderTimeout (Slowloris defense) should not be flagged AST-006; got %q", f.Title)
	}
}

// TestAST006_PartialTimeout_ReadTimeoutOnly_NoFinding mirrors Grafana's
// pkg/api/http_server.go, which sets only ReadTimeout. A single request-phase
// timeout is enough to bound the DoS threat the rule guards against.
func TestAST006_PartialTimeout_ReadTimeoutOnly_NoFinding(t *testing.T) {
	code := `package main

import (
	"net/http"
	"time"
)

func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Addr:        ":8080",
		Handler:     h,
		ReadTimeout: 10 * time.Second,
	}
}
`
	findings := scanGo(code)
	if f := findByRule(findings, "BATOU-AST-006"); f != nil {
		t.Errorf("FP: server with ReadTimeout should not be flagged AST-006; got %q", f.Title)
	}
}

// TestAST006_NoTimeoutAtAll_StillFires is the true-positive guard proving the
// rule was TIGHTENED, not disabled: a server with NO timeout field whatsoever
// is genuinely Slowloris-exploitable and must still fire AST-006.
func TestAST006_NoTimeoutAtAll_StillFires(t *testing.T) {
	code := `package main

import "net/http"

func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Addr:    ":8080",
		Handler: h,
	}
}
`
	findings := scanGo(code)
	if findByRule(findings, "BATOU-AST-006") == nil {
		t.Error("TP lost: http.Server with no timeout fields at all must still fire AST-006")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
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

// AST-008 regression: a sync.WaitGroup-coordinated goroutine cannot leak
// because the parent blocks on wg.Wait() until it exits. The scanner's own
// concurrent rule loop in scanner.scanCore uses exactly this pattern.
func TestAST008_SafeGoroutineBoundedByWaitGroup(t *testing.T) {
	code := `package main

import "sync"

func handler() {
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			doWork(n)
		}(i)
	}
	wg.Wait()
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-008")
	if f != nil {
		t.Errorf("should not flag goroutine bounded by WaitGroup; got: %+v", f)
	}
}

// AST-004 regression: the fuzzy "auth"/"crypt" substring match used to flag
// any method name containing those substrings, including helpers like
// c.checkDeprecatedCryptoImports(). It should only match calls qualified by
// an imported package.
func TestAST004_LocalMethodNamedLikeCrypto(t *testing.T) {
	code := `package main

type checker struct{}

func (c *checker) checkDeprecatedCryptoImports() {}
func (c *checker) validateAuthorization()       {}

func driver() {
	c := &checker{}
	c.checkDeprecatedCryptoImports()
	c.validateAuthorization()
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-004")
	if f != nil {
		t.Errorf("should not flag local-method calls whose names contain 'crypt'/'auth'; got: %+v", f)
	}
}

// AST-004 positive: a real call through an imported bcrypt package still
// fires the fuzzy-match. This guards against the rule fix being too
// permissive.
func TestAST004_StillFlagsImportedBcrypt(t *testing.T) {
	code := `package main

import "golang.org/x/crypto/bcrypt"

func login(pw []byte) {
	bcrypt.CompareHashAndPassword(nil, pw)
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-004")
	if f == nil {
		t.Error("expected BATOU-AST-004 for discarded bcrypt.CompareHashAndPassword call")
	}
}

// FP 3: _, err := f() should NOT be flagged — error IS captured.
func TestAST004_SafeTupleReturnBlankFirst(t *testing.T) {
	code := `package main

import "os"

func handler() error {
	_, err := os.Open("/etc/passwd")
	if err != nil {
		return err
	}
	return nil
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-004")
	if f != nil {
		t.Error("should not flag _, err := os.Open() — error is captured")
	}
}

// FP 3: _, _, err := f() should NOT be flagged — error IS captured.
func TestAST004_SafeMultiBlankWithErr(t *testing.T) {
	code := `package main

import "os"

func doAuthRequest() ([]byte, int, error) {
	return nil, 0, nil
}

func handler() error {
	_, _, err := doAuthRequest()
	if err != nil {
		return err
	}
	return nil
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-004")
	if f != nil {
		t.Error("should not flag _, _, err := f() — error is captured in last position")
	}
}

// Confirm: result, _ := f() STILL flagged — error IS discarded.
func TestAST004_StillFlaggedBlankError(t *testing.T) {
	code := `package main

import "os"

func handler() {
	f, _ := os.Open("/etc/passwd")
	_ = f
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-004")
	if f == nil {
		t.Error("should flag f, _ := os.Open() — error is discarded")
	}
}

// FP 4: Goroutine with context.WithTimeout(context.Background(), ...) is safe.
func TestAST008_SafeGoroutineWithOwnContext(t *testing.T) {
	code := `package main

import (
	"context"
	"time"
)

func handler() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ctx
	}()
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-008")
	if f != nil {
		t.Error("should not flag goroutine that creates its own context via WithTimeout(Background())")
	}
}

// FP 4: Goroutine with context.WithCancel(context.Background()) is safe.
func TestAST008_SafeGoroutineWithOwnCancelContext(t *testing.T) {
	code := `package main

import "context"

func handler() {
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_ = ctx
	}()
}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-008")
	if f != nil {
		t.Error("should not flag goroutine that creates its own context via WithCancel(Background())")
	}
}

// Confirm: bare goroutine without context STILL flagged.
func TestAST008_StillFlaggedNoContext(t *testing.T) {
	code := `package main

func handler() {
	go func() {
		doWork()
	}()
}

func doWork() {}
`
	findings := scanGo(code)
	f := findByRule(findings, "BATOU-AST-008")
	if f == nil {
		t.Error("should still flag goroutine with no context at all")
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

func TestIsLikelyDDLQuery(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  bool
	}{
		// DDL keywords — always identifier-interpolation territory.
		{"create_table", "CREATE TABLE foo (id INT)", true},
		{"alter_add_column", "ALTER TABLE %s ADD COLUMN x", true},
		{"drop_table", "DROP TABLE %s", true},
		{"truncate", "TRUNCATE TABLE %s", true},
		{"rename_table", "RENAME TABLE %s TO %s", true},
		// Engine-specific admin commands (sequence / identity / privileges).
		{"alter_sequence", "ALTER SEQUENCE `%s` RENAME TO `%s`", true},
		{"setval", "SELECT setval('%s', COALESCE((SELECT MAX(id)+1 FROM `%s`), 1), false)", true},
		{"identity_insert_on", "SET IDENTITY_INSERT %s ON", true},
		{"identity_insert_off", "SET IDENTITY_INSERT %s OFF", true},
		{"grant", "GRANT SELECT ON %s TO %s", true},
		{"vacuum_table", "VACUUM ANALYZE %s", true},
		{"reindex_table", "REINDEX TABLE %s", true},

		// DML with identifier slot AND value placeholders → likely safe.
		{"insert_into_with_q", "INSERT INTO %s (a,b) VALUES (?,?)", true},
		{"update_set_with_q", "UPDATE %s SET col=? WHERE id=?", true},
		{"select_from_with_q", "SELECT * FROM %s WHERE id=?", true},
		{"select_from_pg_placeholder", "SELECT * FROM %s WHERE id=$1", true},
		{"backticked_identifier", "INSERT INTO `%s` (a) VALUES (?)", true},
		{"join_with_q", "SELECT a FROM t JOIN %s ON t.id=u.id WHERE t.id=?", true},

		// DML with identifier slot but NO value placeholders — real risk.
		{"insert_into_no_q", "INSERT INTO %s VALUES (%s)", false},
		{"update_set_no_q", "UPDATE %s SET col=%s", false},
		{"select_from_no_q", "SELECT * FROM %s WHERE id=%s", false},

		// Plain DML, no interpolation at all.
		{"plain_insert", "INSERT INTO users (a) VALUES (?)", false},

		// Empty / non-SQL.
		{"empty", "", false},
		{"non_sql", "hello world", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLikelyDDLQuery(tt.query); got != tt.want {
				t.Errorf("isLikelyDDLQuery(%q) = %v, want %v", tt.query, got, tt.want)
			}
		})
	}
}

// =========================================================================
// BATOU-AST-009: Insecure TLS configuration (CWE-295 / CWE-327)
// =========================================================================

func TestAST009_InsecureSkipVerifyTrue(t *testing.T) {
	code := `package main

import "crypto/tls"

func client() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}
`
	f := findByRule(scanGo(code), "BATOU-AST-009")
	if f == nil {
		t.Fatal("expected BATOU-AST-009 for InsecureSkipVerify: true")
	}
	if f.CWEID != "CWE-295" {
		t.Errorf("expected CWE-295, got %s", f.CWEID)
	}
}

func TestAST009_MinVersionTLS10(t *testing.T) {
	code := `package main

import "crypto/tls"

func cfg() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10,
	}
}
`
	f := findByRule(scanGo(code), "BATOU-AST-009")
	if f == nil {
		t.Fatal("expected BATOU-AST-009 for MinVersion: tls.VersionTLS10")
	}
	if f.CWEID != "CWE-327" {
		t.Errorf("expected CWE-327, got %s", f.CWEID)
	}
}

func TestAST009_SkipVerifyFalse_Safe(t *testing.T) {
	// InsecureSkipVerify: false means verification is ENABLED — not a finding.
	code := `package main

import "crypto/tls"

func cfg() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
	}
}
`
	if f := findByRule(scanGo(code), "BATOU-AST-009"); f != nil {
		t.Errorf("did not expect AST-009 on a hardened tls.Config, got: %s", f.Description)
	}
}

func TestAST009_UnrelatedStructField_Safe(t *testing.T) {
	// A field literally named InsecureSkipVerify on a DIFFERENT type must not
	// trigger — anchored on crypto/tls.Config only.
	code := `package main

type MyOpts struct {
	InsecureSkipVerify bool
}

func opts() MyOpts {
	return MyOpts{InsecureSkipVerify: true}
}
`
	if f := findByRule(scanGo(code), "BATOU-AST-009"); f != nil {
		t.Errorf("did not expect AST-009 on an unrelated struct field, got: %s", f.Description)
	}
}

// =========================================================================
// BATOU-AST-010: SSH host key verification (CWE-322)
// =========================================================================

func TestAST010_InsecureIgnoreHostKey(t *testing.T) {
	code := `package main

import "golang.org/x/crypto/ssh"

func cfg() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}
`
	f := findByRule(scanGo(code), "BATOU-AST-010")
	if f == nil {
		t.Fatal("expected BATOU-AST-010 for ssh.InsecureIgnoreHostKey()")
	}
	if f.CWEID != "CWE-322" {
		t.Errorf("expected CWE-322, got %s", f.CWEID)
	}
}

func TestAST010_MissingHostKeyCallback(t *testing.T) {
	code := `package main

import "golang.org/x/crypto/ssh"

func cfg() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: "root",
	}
}
`
	if f := findByRule(scanGo(code), "BATOU-AST-010"); f == nil {
		t.Fatal("expected BATOU-AST-010 for ssh.ClientConfig with no HostKeyCallback")
	}
}

func TestAST010_FixedHostKey_Safe(t *testing.T) {
	code := `package main

import "golang.org/x/crypto/ssh"

func cfg(key ssh.PublicKey) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.FixedHostKey(key),
	}
}
`
	if f := findByRule(scanGo(code), "BATOU-AST-010"); f != nil {
		t.Errorf("did not expect AST-010 when HostKeyCallback is ssh.FixedHostKey, got: %s", f.Description)
	}
}

func TestAST010_UnrelatedHostKeyField_Safe(t *testing.T) {
	// HostKeyCallback on an unrelated type must not trigger.
	code := `package main

type FakeConfig struct {
	HostKeyCallback func() error
}

func cfg() FakeConfig {
	return FakeConfig{}
}
`
	if f := findByRule(scanGo(code), "BATOU-AST-010"); f != nil {
		t.Errorf("did not expect AST-010 on an unrelated type, got: %s", f.Description)
	}
}

// =========================================================================
// BATOU-AST-011: Decompression bomb (CWE-409)
// =========================================================================

func TestAST011_UnboundedGzipCopy(t *testing.T) {
	code := `package main

import (
	"compress/gzip"
	"io"
	"os"
)

func extract(f *os.File, out io.Writer) error {
	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, gr)
	return err
}
`
	f := findByRule(scanGo(code), "BATOU-AST-011")
	if f == nil {
		t.Fatal("expected BATOU-AST-011 for unbounded io.Copy from gzip.Reader")
	}
	if f.CWEID != "CWE-409" {
		t.Errorf("expected CWE-409, got %s", f.CWEID)
	}
}

func TestAST011_BoundedCopyN_Safe(t *testing.T) {
	code := `package main

import (
	"compress/gzip"
	"io"
	"os"
)

const maxBytes = 100 << 20

func extract(f *os.File, out io.Writer) error {
	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	_, err = io.CopyN(out, gr, maxBytes)
	return err
}
`
	if f := findByRule(scanGo(code), "BATOU-AST-011"); f != nil {
		t.Errorf("did not expect AST-011 when io.CopyN bounds the copy, got: %s", f.Description)
	}
}

func TestAST011_LimitReaderWrap_Safe(t *testing.T) {
	code := `package main

import (
	"compress/gzip"
	"io"
	"os"
)

func extract(f *os.File, out io.Writer) error {
	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, io.LimitReader(gr, 100<<20))
	return err
}
`
	if f := findByRule(scanGo(code), "BATOU-AST-011"); f != nil {
		t.Errorf("did not expect AST-011 when source is wrapped in io.LimitReader, got: %s", f.Description)
	}
}

func TestAST011_PlainFileCopy_Safe(t *testing.T) {
	// io.Copy from a plain file (not a decompressor) is not a decompression bomb.
	code := `package main

import (
	"io"
	"os"
)

func cp(src *os.File, out io.Writer) error {
	_, err := io.Copy(out, src)
	return err
}
`
	if f := findByRule(scanGo(code), "BATOU-AST-011"); f != nil {
		t.Errorf("did not expect AST-011 for plain (non-decompressing) io.Copy, got: %s", f.Description)
	}
}

func TestAST010_ZeroValuePlaceholder_Safe(t *testing.T) {
	// A bare zero-value ssh.ClientConfig{} (populated later) must NOT fire —
	// avoids FPs on partial-initialization patterns.
	code := `package main

import "golang.org/x/crypto/ssh"

func cfg() *ssh.ClientConfig {
	c := &ssh.ClientConfig{}
	c.User = "root"
	return c
}
`
	if f := findByRule(scanGo(code), "BATOU-AST-010"); f != nil {
		t.Errorf("did not expect AST-010 on a bare zero-value ssh.ClientConfig{}, got: %s", f.Description)
	}
}
