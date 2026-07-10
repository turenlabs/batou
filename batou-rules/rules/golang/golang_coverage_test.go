package golang

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// ==========================================================================
// BATOU-GO-015: Unhandled error from security-critical function
// ==========================================================================

func TestGO015_IgnoredCryptoError(t *testing.T) {
	content := `package main

import "crypto/aes"

func setup(k []byte) {
	_, _ = aes.NewCipher(k)
}`
	result := testutil.ScanContent(t, "/app/crypto.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-015")
}

func TestGO015_IgnoredX509Error_SingleBlank(t *testing.T) {
	content := `package main

import "crypto/x509"

func parse(der []byte) {
	_ = x509.MarshalPKCS1PrivateKey(key)
}`
	result := testutil.ScanContent(t, "/app/crypto.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-015")
}

func TestGO015_NoSecurityFunc_Safe(t *testing.T) {
	// File never references a security package, so the file pre-gate returns nil early.
	content := `package main

import "fmt"

func main() {
	_, _ = fmt.Println("hello")
}`
	result := testutil.ScanContent(t, "/app/util.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-015")
}

func TestGO015_HandledError_Safe(t *testing.T) {
	// Security package present but the error is captured, not blanked.
	content := `package main

import "crypto/aes"

func setup(k []byte) error {
	block, err := aes.NewCipher(k)
	if err != nil {
		return err
	}
	_ = block
	return nil
}`
	result := testutil.ScanContent(t, "/app/crypto.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-015")
}

func TestGO015_Comment_Ignored(t *testing.T) {
	// The blank-assign pattern appears only inside a comment; should be skipped.
	content := `package main

import "crypto/aes"

func setup(k []byte) {
	// _, _ = aes.NewCipher(k)
	use(k)
}`
	result := testutil.ScanContent(t, "/app/crypto.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-015")
}

// ==========================================================================
// BATOU-GO-016: SQL injection in sqlx named queries
// ==========================================================================

func TestGO016_NamedExec_Sprintf(t *testing.T) {
	content := `package main

import "fmt"

func ins(db *sqlx.DB, table string) {
	db.NamedExec(fmt.Sprintf("INSERT INTO %s (name) VALUES (:name)", table), arg)
}`
	result := testutil.ScanContent(t, "/app/repo.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-016")
}

func TestGO016_NamedQuery_Concat(t *testing.T) {
	content := `package main

func sel(db *sqlx.DB, clause string) {
	db.NamedQuery("SELECT * FROM users WHERE " + clause, arg)
}`
	result := testutil.ScanContent(t, "/app/repo.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-016")
}

func TestGO016_SqlxGet_Sprintf(t *testing.T) {
	content := `package main

import "fmt"

func get(table string) {
	sqlx.Get(&u, fmt.Sprintf("SELECT * FROM %s", table))
}`
	result := testutil.ScanContent(t, "/app/repo.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-016")
}

func TestGO016_NoSqlxReference_Safe(t *testing.T) {
	// Neither "sqlx" nor NamedExec/NamedQuery present — early return.
	content := `package main

import "fmt"

func main() {
	fmt.Println("hi")
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-016")
}

func TestGO016_NamedExec_Parameterized_Safe(t *testing.T) {
	content := `package main

func ins(db *sqlx.DB, user User) {
	db.NamedExec("INSERT INTO users (name) VALUES (:name)", user)
}`
	result := testutil.ScanContent(t, "/app/repo.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-016")
}

func TestGO016_Comment_Ignored(t *testing.T) {
	content := `package main

import "fmt"

func ins(db *sqlx.DB, table string) {
	// db.NamedExec(fmt.Sprintf("INSERT INTO %s", table), arg)
	_ = fmt.Sprintf
}`
	result := testutil.ScanContent(t, "/app/repo.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-016")
}

// ==========================================================================
// BATOU-GO-017: Unsafe reflect.Value usage
// ==========================================================================

func TestGO017_MethodByName_Variable(t *testing.T) {
	content := `package main

import "reflect"

func call(v reflect.Value, name string) {
	v.MethodByName(name).Call(nil)
}`
	result := testutil.ScanContent(t, "/app/dispatch.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-017")
}

func TestGO017_ValueOf_FieldByName(t *testing.T) {
	content := `package main

import "reflect"

func read(obj interface{}, field string) {
	reflect.ValueOf(obj).FieldByName(field)
}`
	result := testutil.ScanContent(t, "/app/dispatch.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-017")
}

func TestGO017_NoReflect_Safe(t *testing.T) {
	content := `package main

import "fmt"

func main() {
	fmt.Println("no reflection here")
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-017")
}

func TestGO017_Comment_Ignored(t *testing.T) {
	content := `package main

import "reflect"

func call(v reflect.Value, name string) {
	/* v.MethodByName(name) */
	_ = reflect.TypeOf(v)
}`
	result := testutil.ScanContent(t, "/app/dispatch.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-017")
}

// ==========================================================================
// BATOU-GO-018: net.Dial without timeout
// ==========================================================================

func TestGO018_NetDial_NoTimeout(t *testing.T) {
	content := `package main

import "net"

func connect(addr string) {
	conn, _ := net.Dial("tcp", addr)
	_ = conn
}`
	result := testutil.ScanContent(t, "/app/net.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-018")
}

func TestGO018_TLSDial_NoTimeout(t *testing.T) {
	content := `package main

import "crypto/tls"

func connect(addr string, cfg *tls.Config) {
	conn, _ := tls.Dial("tcp", addr, cfg)
	_ = conn
}`
	result := testutil.ScanContent(t, "/app/net.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-018")
}

func TestGO018_DialTimeout_Safe(t *testing.T) {
	content := `package main

import (
	"net"
	"time"
)

func connect(addr string) {
	conn, _ := net.DialTimeout("tcp", addr, 5*time.Second)
	_ = conn
}`
	result := testutil.ScanContent(t, "/app/net.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-018")
}

func TestGO018_DialerWithTimeout_Safe(t *testing.T) {
	// reDialerTimeout file-gate suppresses even a bare net.Dial when a Dialer{} is present.
	content := `package main

import (
	"net"
	"time"
)

func connect(addr string) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, _ := d.Dial("tcp", addr)
	_ = conn
}`
	result := testutil.ScanContent(t, "/app/net.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-018")
}

// ==========================================================================
// BATOU-GO-019: Weak file permissions (0666/0664)
// ==========================================================================

func TestGO019_WriteFile_0666(t *testing.T) {
	content := `package main

import "os"

func save(data []byte) {
	os.WriteFile("/tmp/data.txt", data, 0666)
}`
	result := testutil.ScanContent(t, "/app/save.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-019")
}

func TestGO019_OpenFile_0664(t *testing.T) {
	content := `package main

import "os"

func open() {
	os.OpenFile("/tmp/data.txt", os.O_RDWR, 0664)
}`
	result := testutil.ScanContent(t, "/app/save.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-019")
}

func TestGO019_WriteFile_0600_Safe(t *testing.T) {
	content := `package main

import "os"

func save(data []byte) {
	os.WriteFile("/tmp/data.txt", data, 0600)
}`
	result := testutil.ScanContent(t, "/app/save.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-019")
}

func TestGO019_Comment_Ignored(t *testing.T) {
	content := `package main

import "os"

func save(data []byte) {
	// os.WriteFile("/tmp/data.txt", data, 0666)
	os.WriteFile("/tmp/data.txt", data, 0600)
}`
	result := testutil.ScanContent(t, "/app/save.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-019")
}

// ==========================================================================
// BATOU-GO-020: Unsafe use of unsafe.Pointer
// ==========================================================================

func TestGO020_PointerArith(t *testing.T) {
	content := `package main

import "unsafe"

func bump(base unsafe.Pointer, offset uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(base) + offset)
}`
	result := testutil.ScanContent(t, "/app/mem.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-020")
}

func TestGO020_NoUnsafePointer_Safe(t *testing.T) {
	content := `package main

import "fmt"

func main() {
	fmt.Println("safe")
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-020")
}

func TestGO020_PlainPointer_Safe(t *testing.T) {
	// unsafe.Pointer present but no uintptr arithmetic conversion.
	content := `package main

import "unsafe"

func conv(p *int) unsafe.Pointer {
	return unsafe.Pointer(p)
}`
	result := testutil.ScanContent(t, "/app/mem.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-020")
}

func TestGO020_Comment_Ignored(t *testing.T) {
	content := `package main

import "unsafe"

func conv(p *int) unsafe.Pointer {
	// return unsafe.Pointer(uintptr(p) + 8)
	return unsafe.Pointer(p)
}`
	result := testutil.ScanContent(t, "/app/mem.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-020")
}

// ==========================================================================
// BATOU-GO-021: Context cancellation not checked
// ==========================================================================

func TestGO021_UnboundedForLoop_NoCtxCheck(t *testing.T) {
	content := `package main

import "context"

func worker(ctx context.Context) {
	for {
		doWork()
	}
}`
	result := testutil.ScanContent(t, "/app/worker.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-021")
}

func TestGO021_RangeChannel_NoCtxCheck(t *testing.T) {
	content := `package main

import "context"

func worker(ctx context.Context, ch chan int) {
	for msg := range ch {
		process(msg)
	}
}`
	result := testutil.ScanContent(t, "/app/worker.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-021")
}

func TestGO021_WithCtxDone_Safe(t *testing.T) {
	content := `package main

import "context"

func worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			doWork()
		}
	}
}`
	result := testutil.ScanContent(t, "/app/worker.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-021")
}

func TestGO021_NoCtxParam_Safe(t *testing.T) {
	// No context.Context parameter — file pre-gate returns nil.
	content := `package main

func worker() {
	for {
		doWork()
	}
}`
	result := testutil.ScanContent(t, "/app/worker.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-021")
}

func TestGO021_BoundedRange_Safe(t *testing.T) {
	// Bounded slice iteration in a ctx-bearing func is intentionally NOT flagged.
	content := `package main

import "context"

func worker(ctx context.Context, items []string) {
	for _, item := range items {
		process(item)
	}
}`
	result := testutil.ScanContent(t, "/app/worker.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-021")
}

// ==========================================================================
// BATOU-GO-022: ResponseWriter used after handler returns
// ==========================================================================

func TestGO022_ResponseWriterInGoroutine(t *testing.T) {
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	go func() { w.Write([]byte("late")) }()
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-022")
}

func TestGO022_NotInHandler_Safe(t *testing.T) {
	// No HTTP handler signature in the file — isInHTTPHandler gate returns nil.
	content := `package main

func compute() {
	go func() { doSomething() }()
}`
	result := testutil.ScanContent(t, "/app/compute.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-022")
}

// ==========================================================================
// BATOU-GO-023: Unbounded goroutine creation
// ==========================================================================

func TestGO023_GoroutineInForLoop(t *testing.T) {
	content := `package main

func fanOut(items []int) {
	for i := 0; i < len(items); i++ {
		go func(x int) { process(x) }(items[i])
	}
}`
	result := testutil.ScanContent(t, "/app/fanout.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-023")
}

func TestGO023_GoroutineInRange(t *testing.T) {
	content := `package main

func fanOut(items []int) {
	for _, item := range items {
		go process(item)
	}
}`
	result := testutil.ScanContent(t, "/app/fanout.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-023")
}

func TestGO023_WithWaitGroup_Safe(t *testing.T) {
	// reSemaphore file-gate (sync.WaitGroup) suppresses the rule.
	content := `package main

import "sync"

func fanOut(items []int) {
	var wg sync.WaitGroup
	for _, item := range items {
		wg.Add(1)
		go func(x int) { defer wg.Done(); process(x) }(item)
	}
	wg.Wait()
}`
	result := testutil.ScanContent(t, "/app/fanout.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-023")
}

func TestGO023_GoroutineOutsideLoop_Safe(t *testing.T) {
	content := `package main

func launch() {
	go process(42)
}`
	result := testutil.ScanContent(t, "/app/launch.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-023")
}

// ==========================================================================
// BATOU-GO-024: SSRF via net/http default client
// ==========================================================================

func TestGO024_HTTPGet_UserInput(t *testing.T) {
	content := `package main

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("target")
	resp, _ := http.Get(url)
	_ = resp
}`
	result := testutil.ScanContent(t, "/app/proxy.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-024")
}

func TestGO024_NoUserInput_Safe(t *testing.T) {
	// http.Get present but no HTTP user-input source in the file.
	content := `package main

import "net/http"

func fetch() {
	resp, _ := http.Get("https://example.com/static")
	_ = resp
}`
	result := testutil.ScanContent(t, "/app/proxy.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-024")
}

func TestGO024_CustomClientWithCheckRedirect_Safe(t *testing.T) {
	// http.Client{} config + CheckRedirect both present -> suppressed.
	content := `package main

import "net/http"

func fetch(r *http.Request) {
	c := r.URL.Query().Get("u")
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, _ := client.Get(c)
	_ = resp
}`
	result := testutil.ScanContent(t, "/app/proxy.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-024")
}

// ==========================================================================
// BATOU-GO-025: Insecure gRPC without TLS
// ==========================================================================

func TestGO025_GRPCDialWithInsecure(t *testing.T) {
	content := `package main

import "google.golang.org/grpc"

func connect(addr string) {
	conn, _ := grpc.Dial(addr, grpc.WithInsecure())
	_ = conn
}`
	result := testutil.ScanContent(t, "/app/grpc.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-025")
}

func TestGO025_GRPCInsecureCredentials(t *testing.T) {
	content := `package main

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func connect(addr string) {
	conn, _ := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	_ = conn
}`
	result := testutil.ScanContent(t, "/app/grpc.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-025")
}

func TestGO025_GRPCNewServerNoTLS(t *testing.T) {
	content := `package main

import "google.golang.org/grpc"

func serve() {
	s := grpc.NewServer()
	_ = s
}`
	result := testutil.ScanContent(t, "/app/grpc.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-025")
}

func TestGO025_GRPCNewServerWithCreds_Safe(t *testing.T) {
	// grpc.NewServer() present but grpc.Creds / credentials.NewTLS in file -> suppressed.
	content := `package main

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func serve(cfg *tls.Config) {
	creds := credentials.NewTLS(cfg)
	s := grpc.NewServer(grpc.Creds(creds))
	_ = s
}`
	result := testutil.ScanContent(t, "/app/grpc.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-025")
}

func TestGO025_NoGRPC_Safe(t *testing.T) {
	content := `package main

import "fmt"

func main() {
	fmt.Println("no grpc")
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-025")
}

// ==========================================================================
// BATOU-GO-026: exec.Command with user input
// ==========================================================================

func TestGO026_ExecCommand_UserInput(t *testing.T) {
	content := `package main

import (
	"net/http"
	"os/exec"
)

func run(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command(r.URL.Query().Get("cmd"))
	_ = cmd
}`
	result := testutil.ScanContent(t, "/app/run.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-026")
}

func TestGO026_ExecCommand_GinQuery(t *testing.T) {
	content := `package main

import "os/exec"

func run(c *gin.Context) {
	cmd := exec.Command(c.Query("cmd"))
	_ = cmd
}`
	result := testutil.ScanContent(t, "/app/run.go", content)
	testutil.MustFindRule(t, result, "BATOU-GO-026")
}

func TestGO026_NoExecCommand_Safe(t *testing.T) {
	content := `package main

import "fmt"

func main() {
	fmt.Println("no exec")
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-026")
}

func TestGO026_ExecCommand_StaticArg_Safe(t *testing.T) {
	content := `package main

import "os/exec"

func run() {
	cmd := exec.Command("ls", "-la")
	_ = cmd
}`
	result := testutil.ScanContent(t, "/app/run.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GO-026")
}

// ==========================================================================
// Metadata methods (ID / Name / Description / DefaultSeverity / Languages)
// for every rule in golang.go and golang_ext.go.
// ==========================================================================

func TestRuleMetadata(t *testing.T) {
	allRules := []rules.Rule{
		// golang.go
		&GORMSQLInjection{}, &TemplateHTMLBypass{}, &ListenAndServeNoTLS{},
		&BindWithoutValidation{}, &FilepathTraversal{}, &MathRandCrypto{},
		&GoroutineLeak{}, &RaceConditionHandler{}, &UnvalidatedRedirect{},
		&MissingCSRF{}, &HardcodedJWTSecret{}, &PermissiveFileMode{},
		&TrustedProxyMisconfig{}, &UnsafeHTTPResponse{},
		// golang_ext.go
		&UnhandledSecurityError{}, &SQLXInjection{}, &UnsafeReflect{},
		&NetDialNoTimeout{}, &WeakFilePerms{}, &UnsafePointerUse{},
		&ContextNotChecked{}, &ResponseWriterRace{}, &UnboundedGoroutine{},
		&SSRFDefaultClient{}, &GRPCWithoutTLS{}, &ExecUnsanitizedEnv{},
	}

	seen := make(map[string]bool)
	for _, r := range allRules {
		id := r.ID()
		if id == "" || !strings.HasPrefix(id, "BATOU-GO-") {
			t.Errorf("rule %T has unexpected ID %q", r, id)
		}
		if seen[id] {
			t.Errorf("duplicate rule ID %q", id)
		}
		seen[id] = true
		if r.Name() == "" {
			t.Errorf("rule %s has empty Name", id)
		}
		if len(r.Languages()) == 0 || r.Languages()[0] != rules.LangGo {
			t.Errorf("rule %s should be a Go rule, got %v", id, r.Languages())
		}
		// DefaultSeverity should produce a non-empty label.
		if r.DefaultSeverity().String() == "" {
			t.Errorf("rule %s has empty severity label", id)
		}
	}

	// Description() is defined on the concrete types (not part of the minimal
	// rules.Rule interface for all), so exercise it via type assertion.
	type described interface{ Description() string }
	for _, r := range allRules {
		if d, ok := r.(described); ok {
			if strings.TrimSpace(d.Description()) == "" {
				t.Errorf("rule %s has empty Description", r.ID())
			}
		}
	}
}

// ==========================================================================
// Unexported helper coverage
// ==========================================================================

func TestHelper_truncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate short: got %q", got)
	}
	long := strings.Repeat("a", 20)
	got := truncate(long, 5)
	if got != "aaaaa..." {
		t.Errorf("truncate long: got %q", got)
	}
	// Exactly at the boundary: len == maxLen should not truncate.
	if got := truncate("aaaaa", 5); got != "aaaaa" {
		t.Errorf("truncate boundary: got %q", got)
	}
}

func TestHelper_isComment(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"// a line comment", true},
		{"   // indented comment", true},
		{"/* block start", true},
		{" * continuation of block", true},
		{"x := 1 // trailing", false},
		{"func main() {", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isComment(c.line); got != c.want {
			t.Errorf("isComment(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestHelper_surroundingContext(t *testing.T) {
	lines := []string{"l0", "l1", "l2", "l3", "l4"}
	// Middle with radius clamps to bounds correctly.
	got := surroundingContext(lines, 2, 1)
	if got != "l1\nl2\nl3" {
		t.Errorf("surroundingContext middle: got %q", got)
	}
	// idx near start clamps low bound to 0.
	got = surroundingContext(lines, 0, 2)
	if got != "l0\nl1\nl2" {
		t.Errorf("surroundingContext start: got %q", got)
	}
	// idx near end clamps high bound to len.
	got = surroundingContext(lines, 4, 3)
	if got != "l1\nl2\nl3\nl4" {
		t.Errorf("surroundingContext end: got %q", got)
	}
}

func TestHelper_hasNearbyUserInput(t *testing.T) {
	lines := []string{
		"func h(w http.ResponseWriter, r *http.Request) {",
		"  id := r.URL.Query().Get(\"id\")",
		"  use(id)",
		"}",
	}
	// Window includes the request source line -> true.
	if !hasNearbyUserInput(lines, 2, 2) {
		t.Errorf("hasNearbyUserInput: expected true near request source")
	}
	// No user input anywhere -> false.
	noInput := []string{"a := 1", "b := 2", "c := 3"}
	if hasNearbyUserInput(noInput, 1, 1) {
		t.Errorf("hasNearbyUserInput: expected false with no source")
	}
	// Source outside the window -> false.
	if hasNearbyUserInput(lines, 3, 0) {
		t.Errorf("hasNearbyUserInput: source outside window should be false")
	}
}

func TestHelper_isLocalOrParamVar(t *testing.T) {
	lines := []string{
		"func handler(w http.ResponseWriter, r *http.Request, cache map[string]int) {",
		"  cache[id] = 1",
		"}",
	}
	// cache is a function parameter -> true.
	if !isLocalOrParamVar(lines, 1, "cache") {
		t.Errorf("isLocalOrParamVar: expected true for func parameter")
	}

	localDecl := []string{
		"func handler() {",
		"  data := make(map[string]int)",
		"  data[k] = 1",
		"}",
	}
	// data declared with := -> true.
	if !isLocalOrParamVar(localDecl, 2, "data") {
		t.Errorf("isLocalOrParamVar: expected true for := local")
	}

	pkgLevel := []string{
		"var cache = map[string]int{}",
		"func handler() {",
		"  cache[k] = 1",
		"}",
	}
	// cache is package-level (not a param, not a local in the function) -> false.
	if isLocalOrParamVar(pkgLevel, 2, "cache") {
		t.Errorf("isLocalOrParamVar: expected false for package-level var")
	}

	makeDecl := []string{
		"func handler() {",
		"  var m = make(map[string]int)",
		"  m[k] = 1",
		"}",
	}
	if !isLocalOrParamVar(makeDecl, 2, "m") {
		t.Errorf("isLocalOrParamVar: expected true for var = make() local")
	}

	unmarshalDecl := []string{
		"func handler(body []byte) {",
		"  json.Unmarshal(body, &payload)",
		"  payload[k] = 1",
		"}",
	}
	if !isLocalOrParamVar(unmarshalDecl, 2, "payload") {
		t.Errorf("isLocalOrParamVar: expected true for json.Unmarshal target")
	}
}
