package golang

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Extension patterns for GO-015 through GO-026
// ---------------------------------------------------------------------------

// GO-015: Unhandled error from security-critical function
var (
	reSecurityFuncCall = regexp.MustCompile(`\b(?:tls|crypto|auth|x509|cipher|aes|rsa|ecdsa|ed25519|hmac|sha256|sha512|bcrypt|scrypt|argon2|pbkdf2)\.`)
	reErrIgnored       = regexp.MustCompile(`[^,\s]\s*=\s*(?:tls|crypto|auth|x509|cipher|aes|rsa|ecdsa|ed25519|hmac|sha256|sha512|bcrypt|scrypt|argon2|pbkdf2)\.`)
	reBlankErrAssign   = regexp.MustCompile(`_\s*(?:,\s*_\s*)?=\s*(?:tls|crypto|auth|x509|cipher|aes|rsa|ecdsa|ed25519|hmac|sha256|sha512|bcrypt|scrypt|argon2|pbkdf2)\.`)
)

// GO-016: SQL injection in sqlx named queries
var (
	reSQLXNamedFmt    = regexp.MustCompile(`\b(?:db|tx)\s*\.\s*(?:NamedExec|NamedQuery|PrepareNamed)\s*\(\s*fmt\.Sprintf\s*\(`)
	reSQLXNamedConcat = regexp.MustCompile(`\b(?:db|tx)\s*\.\s*(?:NamedExec|NamedQuery|PrepareNamed)\s*\(\s*(?:"[^"]*"\s*\+|[a-zA-Z_]\w*\s*\+)`)
	reSQLXGetConcat   = regexp.MustCompile(`\bsqlx?\s*\.\s*(?:Get|Select|MustExec|Exec|Query|QueryRow)\s*\([^,]*,\s*fmt\.Sprintf\s*\(`)
)

// GO-017: Unsafe reflect.Value usage
var (
	reReflectMethodByName = regexp.MustCompile(`\.MethodByName\s*\(\s*[a-zA-Z_]\w*\s*\)`)
	reReflectCall         = regexp.MustCompile(`\.Call\s*\(`)
	reReflectFieldByName  = regexp.MustCompile(`reflect\.ValueOf\s*\([^)]+\)\s*\.\s*(?:MethodByName|FieldByName)\s*\(`)
)

// GO-018: net.Dial without timeout
var (
	reNetDial       = regexp.MustCompile(`\bnet\.Dial\s*\(`)
	reNetDialTLS    = regexp.MustCompile(`\btls\.Dial\s*\(`)
	reDialTimeout   = regexp.MustCompile(`\bnet\.DialTimeout\b`)
	reDialerTimeout = regexp.MustCompile(`\bnet\.Dialer\s*\{`)
)

// GO-019: Weak file permissions
var (
	reWriteFilePerm666 = regexp.MustCompile(`os\.WriteFile\s*\([^,]+,[^,]+,\s*0o?(?:666|664|660)\s*\)`)
	reOpenFilePerm666  = regexp.MustCompile(`os\.OpenFile\s*\([^,]+,[^,]+,\s*0o?(?:666|664|660)\s*\)`)
)

// GO-020: Unsafe use of unsafe.Pointer
var (
	reUnsafePointer     = regexp.MustCompile(`unsafe\.Pointer\s*\(`)
	reUintptrConversion = regexp.MustCompile(`uintptr\s*\(\s*unsafe\.Pointer`)
	rePointerArith      = regexp.MustCompile(`unsafe\.Pointer\s*\(\s*uintptr\s*\(`)
)

// GO-021: Context cancellation not checked
var (
	reForLoop        = regexp.MustCompile(`\bfor\s+(?:\{|.*;.*;)`)
	reForRange       = regexp.MustCompile(`\bfor\s+.*range\b`)
	reCtxCheck       = regexp.MustCompile(`ctx\.(?:Done|Err|Deadline)\s*\(|select\s*\{|case\s*<-\s*ctx`)
	reCtxParam       = regexp.MustCompile(`\bctx\s+context\.Context\b`)
)

// GO-022: ResponseWriter used after handler returns
var (
	reGoWriteAfterReturn = regexp.MustCompile(`go\s+func\s*\([^)]*\)\s*\{[^}]*(?:w\.Write|w\.WriteHeader|w\.Header|fmt\.Fprint)`)
	reDeferResp          = regexp.MustCompile(`\bdefer\s+.*(?:w\.Write|w\.WriteHeader|ResponseWriter)`)
)

// GO-023: Unbounded goroutine creation
var (
	reGoInLoop      = regexp.MustCompile(`\bgo\s+(?:func\s*\(|[a-zA-Z_]\w*\s*\()`)
	reSemaphore     = regexp.MustCompile(`(?:semaphore|errgroup|sync\.WaitGroup|make\s*\(\s*chan\s+struct\s*\{\s*\}\s*,|worker[Pp]ool|goroutine[Pp]ool|ants\.|tunny\.)`)
)

// GO-024: SSRF via net/http default client
var (
	reHTTPDefaultClient = regexp.MustCompile(`\bhttp\.(?:Get|Post|PostForm|Head)\s*\(`)
	reHTTPClientConfig  = regexp.MustCompile(`\bhttp\.Client\s*\{`)
	reCheckRedirect     = regexp.MustCompile(`CheckRedirect\s*:`)
)

// GO-025: Insecure gRPC without TLS
var (
	reGRPCDialInsecure     = regexp.MustCompile(`grpc\.Dial\s*\([^)]*grpc\.WithInsecure\s*\(\s*\)`)
	reGRPCDialNoTransport  = regexp.MustCompile(`grpc\.WithTransportCredentials\s*\(\s*insecure\.NewCredentials\s*\(\s*\)\s*\)`)
	reGRPCNewServerNoTLS   = regexp.MustCompile(`grpc\.NewServer\s*\(\s*\)`)
	reGRPCServerCreds      = regexp.MustCompile(`grpc\.Creds\s*\(|credentials\.NewTLS`)
)

// GO-026: os.Exec with unsanitized environment
var (
	reExecCmdEnv     = regexp.MustCompile(`exec\.Command\s*\([^)]*\)\s*\.\s*Env\s*=`)
	reExecEnvAppend  = regexp.MustCompile(`\.Env\s*=\s*append\s*\(\s*os\.Environ\s*\(\s*\)`)
	reExecCmdRun     = regexp.MustCompile(`exec\.Command\s*\(`)
	reExecCmdUserVar = regexp.MustCompile(`exec\.Command\s*\(\s*(?:r\.(?:URL\.Query|FormValue|PostFormValue|Header\.Get)|(?:c|ctx)\.(?:Query|Param|QueryParam|FormValue))\s*\(`)
)

func init() {
	rules.Register(&UnhandledSecurityError{})
	rules.Register(&SQLXInjection{})
	rules.Register(&UnsafeReflect{})
	rules.Register(&NetDialNoTimeout{})
	rules.Register(&WeakFilePerms{})
	rules.Register(&UnsafePointerUse{})
	rules.Register(&ContextNotChecked{})
	rules.Register(&ResponseWriterRace{})
	rules.Register(&UnboundedGoroutine{})
	rules.Register(&SSRFDefaultClient{})
	rules.Register(&GRPCWithoutTLS{})
	rules.Register(&ExecUnsanitizedEnv{})
}

// ---------------------------------------------------------------------------
// GO-015: Unhandled error from security-critical function
// ---------------------------------------------------------------------------

type UnhandledSecurityError struct{}

func (r *UnhandledSecurityError) ID() string                      { return "GTSS-GO-015" }
func (r *UnhandledSecurityError) Name() string                    { return "UnhandledSecurityError" }
func (r *UnhandledSecurityError) DefaultSeverity() rules.Severity { return rules.High }
func (r *UnhandledSecurityError) Description() string {
	return "Detects ignored errors from security-critical functions (crypto, auth, tls) that may silently fail."
}
func (r *UnhandledSecurityError) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *UnhandledSecurityError) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reSecurityFuncCall.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reBlankErrAssign.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ignored error from security-critical function",
				Description:   "Errors from crypto/tls/auth functions are discarded with a blank identifier. A silently failing security operation (e.g., failed TLS handshake, invalid hash) leaves the system in an insecure state.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Always check errors from security-critical functions. Handle failures by aborting the operation or returning an error to the caller.",
				CWEID:         "CWE-252",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "error-handling", "crypto"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GO-016: SQL injection in sqlx named queries
// ---------------------------------------------------------------------------

type SQLXInjection struct{}

func (r *SQLXInjection) ID() string                      { return "GTSS-GO-016" }
func (r *SQLXInjection) Name() string                    { return "SQLXInjection" }
func (r *SQLXInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *SQLXInjection) Description() string {
	return "Detects SQL injection in sqlx named queries using fmt.Sprintf or string concatenation."
}
func (r *SQLXInjection) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *SQLXInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "sqlx") && !strings.Contains(ctx.Content, "NamedExec") && !strings.Contains(ctx.Content, "NamedQuery") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		var matched string
		if m := reSQLXNamedFmt.FindString(line); m != "" {
			matched = m
		} else if m := reSQLXNamedConcat.FindString(line); m != "" {
			matched = m
		} else if m := reSQLXGetConcat.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SQL injection in sqlx query via string interpolation",
				Description:   "sqlx named queries built with fmt.Sprintf or concatenation bypass parameterized query protection, enabling SQL injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use sqlx parameterized queries: db.NamedExec(\"INSERT INTO users (name) VALUES (:name)\", user). Never use fmt.Sprintf to build SQL.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "sqlx", "sql-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GO-017: Unsafe reflect.Value usage
// ---------------------------------------------------------------------------

type UnsafeReflect struct{}

func (r *UnsafeReflect) ID() string                      { return "GTSS-GO-017" }
func (r *UnsafeReflect) Name() string                    { return "UnsafeReflect" }
func (r *UnsafeReflect) DefaultSeverity() rules.Severity { return rules.High }
func (r *UnsafeReflect) Description() string {
	return "Detects unsafe reflect.Value usage allowing arbitrary method calls via MethodByName with user input."
}
func (r *UnsafeReflect) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *UnsafeReflect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "reflect") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		var matched string
		if m := reReflectMethodByName.FindString(line); m != "" {
			matched = m
		} else if m := reReflectFieldByName.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe reflect usage: arbitrary method/field access via variable name",
				Description:   "MethodByName/FieldByName with a variable argument allows calling arbitrary methods or accessing fields based on runtime input. If the name is user-controlled, this enables invoking unintended operations.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use an explicit allowlist of permitted method/field names instead of passing user input directly to MethodByName/FieldByName.",
				CWEID:         "CWE-470",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "reflect", "arbitrary-call"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GO-018: net.Dial without timeout
// ---------------------------------------------------------------------------

type NetDialNoTimeout struct{}

func (r *NetDialNoTimeout) ID() string                      { return "GTSS-GO-018" }
func (r *NetDialNoTimeout) Name() string                    { return "NetDialNoTimeout" }
func (r *NetDialNoTimeout) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NetDialNoTimeout) Description() string {
	return "Detects net.Dial/tls.Dial without timeout, which can hang indefinitely causing DoS."
}
func (r *NetDialNoTimeout) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *NetDialNoTimeout) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if reDialTimeout.MatchString(ctx.Content) || reDialerTimeout.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		var matched string
		if m := reNetDial.FindString(line); m != "" {
			matched = m
		} else if m := reNetDialTLS.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "net.Dial/tls.Dial without timeout (potential DoS)",
				Description:   "net.Dial and tls.Dial block indefinitely if the remote host does not respond. In a server context, this can exhaust goroutines and file descriptors, leading to denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use net.DialTimeout or net.Dialer{Timeout: 10*time.Second} to set a connection timeout. Also set read/write deadlines on the connection after dialing.",
				CWEID:         "CWE-400",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"go", "timeout", "dos", "network"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GO-019: Weak file permissions (0666/0664)
// ---------------------------------------------------------------------------

type WeakFilePerms struct{}

func (r *WeakFilePerms) ID() string                      { return "GTSS-GO-019" }
func (r *WeakFilePerms) Name() string                    { return "WeakFilePerms" }
func (r *WeakFilePerms) DefaultSeverity() rules.Severity { return rules.High }
func (r *WeakFilePerms) Description() string {
	return "Detects os.WriteFile/os.OpenFile with overly permissive file modes (0666, 0664)."
}
func (r *WeakFilePerms) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *WeakFilePerms) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		var matched string
		if m := reWriteFilePerm666.FindString(line); m != "" {
			matched = m
		} else if m := reOpenFilePerm666.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Weak file permissions: world-readable/writable file mode",
				Description:   "File created with mode 0666 or 0664 allows all users on the system to read and potentially write the file. Sensitive data such as credentials, tokens, or configuration can be exposed.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use restrictive permissions: 0600 for sensitive files (owner read/write only), 0640 for files shared with a group.",
				CWEID:         "CWE-732",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "file-permissions", "weak-permissions"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GO-020: Unsafe use of unsafe.Pointer
// ---------------------------------------------------------------------------

type UnsafePointerUse struct{}

func (r *UnsafePointerUse) ID() string                      { return "GTSS-GO-020" }
func (r *UnsafePointerUse) Name() string                    { return "UnsafePointerUse" }
func (r *UnsafePointerUse) DefaultSeverity() rules.Severity { return rules.High }
func (r *UnsafePointerUse) Description() string {
	return "Detects unsafe.Pointer arithmetic patterns that can cause memory corruption or out-of-bounds access."
}
func (r *UnsafePointerUse) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *UnsafePointerUse) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "unsafe.Pointer") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := rePointerArith.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe pointer arithmetic via uintptr conversion",
				Description:   "Converting unsafe.Pointer to uintptr for arithmetic and back to unsafe.Pointer bypasses Go's memory safety guarantees. If the GC moves the pointed-to object between the conversions, the resulting pointer becomes invalid, causing memory corruption.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use unsafe.Add() (Go 1.17+) for pointer arithmetic. If manual arithmetic is needed, perform the entire conversion in a single expression so the GC cannot intervene.",
				CWEID:         "CWE-787",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "unsafe", "memory-safety"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GO-021: Context cancellation not checked in long operation
// ---------------------------------------------------------------------------

type ContextNotChecked struct{}

func (r *ContextNotChecked) ID() string                      { return "GTSS-GO-021" }
func (r *ContextNotChecked) Name() string                    { return "ContextNotChecked" }
func (r *ContextNotChecked) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ContextNotChecked) Description() string {
	return "Detects long-running loops in functions with context.Context parameter that do not check ctx.Done()."
}
func (r *ContextNotChecked) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *ContextNotChecked) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reCtxParam.MatchString(ctx.Content) {
		return nil
	}
	if reCtxCheck.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reForLoop.MatchString(line) || reForRange.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Loop in context-aware function without ctx.Done() check",
				Description:   "A loop in a function that accepts context.Context does not check ctx.Done(). If the context is cancelled (e.g., client disconnect, timeout), the loop continues wasting resources and preventing graceful shutdown.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Check ctx.Done() in the loop: select { case <-ctx.Done(): return ctx.Err() default: }. For range loops over channels, use for-select pattern.",
				CWEID:         "CWE-404",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"go", "context", "cancellation", "resource-leak"},
			})
			break // one finding per file
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GO-022: ResponseWriter used after handler returns
// ---------------------------------------------------------------------------

type ResponseWriterRace struct{}

func (r *ResponseWriterRace) ID() string                      { return "GTSS-GO-022" }
func (r *ResponseWriterRace) Name() string                    { return "ResponseWriterRace" }
func (r *ResponseWriterRace) DefaultSeverity() rules.Severity { return rules.High }
func (r *ResponseWriterRace) Description() string {
	return "Detects ResponseWriter usage in deferred functions or goroutines that may execute after the handler returns."
}
func (r *ResponseWriterRace) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *ResponseWriterRace) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !isInHTTPHandler(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reGoWriteAfterReturn.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ResponseWriter used in goroutine (race condition)",
				Description:   "http.ResponseWriter is used in a goroutine spawned from an HTTP handler. After the handler returns, the ResponseWriter is no longer valid. Writing to it causes a data race and may panic or corrupt the response.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Complete all ResponseWriter operations before the handler returns. If background work is needed, copy required data and signal completion via channels or use middleware that extends the response lifecycle.",
				CWEID:         "CWE-362",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "race-condition", "http", "response-writer"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GO-023: Unbounded goroutine creation from user input
// ---------------------------------------------------------------------------

type UnboundedGoroutine struct{}

func (r *UnboundedGoroutine) ID() string                      { return "GTSS-GO-023" }
func (r *UnboundedGoroutine) Name() string                    { return "UnboundedGoroutine" }
func (r *UnboundedGoroutine) DefaultSeverity() rules.Severity { return rules.High }
func (r *UnboundedGoroutine) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }
func (r *UnboundedGoroutine) Description() string {
	return "Detects goroutine creation inside loops without concurrency limits (semaphore, worker pool), risking OOM."
}

func (r *UnboundedGoroutine) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if reSemaphore.MatchString(ctx.Content) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	inLoop := false
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reForLoop.MatchString(line) || reForRange.MatchString(line) {
			inLoop = true
		}
		if inLoop && reGoInLoop.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unbounded goroutine creation in loop",
				Description:   "Spawning goroutines inside a loop without a concurrency limiter can create millions of goroutines from user-controlled input (e.g., large request payloads). This leads to OOM kills and denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use a worker pool pattern, errgroup with SetLimit(), or a buffered channel semaphore to bound concurrency: sem := make(chan struct{}, maxWorkers); sem <- struct{}{}; go func() { defer func() { <-sem }(); ... }()",
				CWEID:         "CWE-770",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "goroutine", "unbounded", "dos"},
			})
			break // one finding per file
		}
		if strings.Contains(line, "}") && inLoop {
			inLoop = false
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GO-024: SSRF via net/http default client
// ---------------------------------------------------------------------------

type SSRFDefaultClient struct{}

func (r *SSRFDefaultClient) ID() string                      { return "GTSS-GO-024" }
func (r *SSRFDefaultClient) Name() string                    { return "SSRFDefaultClient" }
func (r *SSRFDefaultClient) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SSRFDefaultClient) Description() string {
	return "Detects http.Get/Post with user-controlled URLs using the default client (no redirect limit or timeout)."
}
func (r *SSRFDefaultClient) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *SSRFDefaultClient) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if reHTTPClientConfig.MatchString(ctx.Content) && reCheckRedirect.MatchString(ctx.Content) {
		return nil
	}
	if !hasNearbyUserInput(strings.Split(ctx.Content, "\n"), 0, len(strings.Split(ctx.Content, "\n"))) {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reHTTPDefaultClient.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "http.Get/Post with default client (no redirect limit)",
				Description:   "http.Get/Post/PostForm use the default http.Client which follows up to 10 redirects and has no timeout. Combined with user-controlled URLs, this enables SSRF, redirect-based attacks, and resource exhaustion.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use a custom http.Client with CheckRedirect, Timeout, and Transport configured: client := &http.Client{Timeout: 10*time.Second, CheckRedirect: func(...) error { return http.ErrUseLastResponse }}",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-Server-Side Request Forgery",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"go", "ssrf", "http-client", "redirect"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GO-025: Insecure gRPC without TLS credentials
// ---------------------------------------------------------------------------

type GRPCWithoutTLS struct{}

func (r *GRPCWithoutTLS) ID() string                      { return "GTSS-GO-025" }
func (r *GRPCWithoutTLS) Name() string                    { return "GRPCWithoutTLS" }
func (r *GRPCWithoutTLS) DefaultSeverity() rules.Severity { return rules.High }
func (r *GRPCWithoutTLS) Description() string {
	return "Detects gRPC connections and servers created without TLS credentials, transmitting data in plaintext."
}
func (r *GRPCWithoutTLS) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *GRPCWithoutTLS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "grpc") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		var matched string
		var desc string
		if m := reGRPCDialInsecure.FindString(line); m != "" {
			matched = m
			desc = "grpc.Dial with grpc.WithInsecure() (deprecated, plaintext)"
		} else if m := reGRPCDialNoTransport.FindString(line); m != "" {
			matched = m
			desc = "gRPC client with insecure.NewCredentials() (plaintext)"
		} else if reGRPCNewServerNoTLS.MatchString(line) && !reGRPCServerCreds.MatchString(ctx.Content) {
			matched = strings.TrimSpace(line)
			desc = "gRPC server without TLS credentials"
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Insecure gRPC: " + desc,
				Description:   "gRPC without TLS transmits all data (including authentication tokens, sensitive business data) in plaintext. Any network observer can intercept and modify the traffic.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use credentials.NewTLS() for gRPC clients and grpc.Creds() for servers: creds := credentials.NewTLS(&tls.Config{...}); conn, _ := grpc.Dial(addr, grpc.WithTransportCredentials(creds))",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "grpc", "tls", "plaintext"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GO-026: os.Exec with unsanitized environment variables
// ---------------------------------------------------------------------------

type ExecUnsanitizedEnv struct{}

func (r *ExecUnsanitizedEnv) ID() string                      { return "GTSS-GO-026" }
func (r *ExecUnsanitizedEnv) Name() string                    { return "ExecUnsanitizedEnv" }
func (r *ExecUnsanitizedEnv) DefaultSeverity() rules.Severity { return rules.High }
func (r *ExecUnsanitizedEnv) Description() string {
	return "Detects exec.Command with user-controlled arguments or unsanitized environment variable injection."
}
func (r *ExecUnsanitizedEnv) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *ExecUnsanitizedEnv) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !strings.Contains(ctx.Content, "exec.Command") {
		return nil
	}
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reExecCmdUserVar.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Command injection via exec.Command with user input",
				Description:   "exec.Command is called with user-controlled HTTP input as the command or arguments. While exec.Command does not invoke a shell, the command name itself or arguments could allow executing arbitrary programs or exploiting argument injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Never use user input as the command name. Use an allowlist for permitted commands and validate/sanitize all arguments. Consider using filepath.Base() to prevent path traversal in command names.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"go", "exec", "command-injection", "environment"},
			})
		}
	}
	return findings
}
