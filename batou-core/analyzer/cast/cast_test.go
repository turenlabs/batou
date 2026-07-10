package cast

import (
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
	"testing"
)

func scanC(code string) []rules.Finding {
	tree := ast.Parse([]byte(code), rules.LangC)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.c",
		Content:  code,
		Language: rules.LangC,
		Tree:     tree,
	}
	a := &CASTAnalyzer{}
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

func TestBannedFunctions(t *testing.T) {
	code := `
#include <string.h>
void handler(char *input) {
    char buf[64];
    gets(buf);
    strcpy(buf, input);
    strcat(buf, input);
}
`
	findings := scanC(code)
	count := countByRule(findings, "BATOU-CAST-001")
	if count != 3 {
		t.Errorf("expected 3 banned function findings, got %d", count)
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestSprintfBanned(t *testing.T) {
	code := `
void handler(char *input) {
    char buf[64];
    sprintf(buf, "%s", input);
}
`
	findings := scanC(code)
	f := findByRule(findings, "BATOU-CAST-001")
	if f == nil {
		t.Error("expected banned function finding for sprintf")
	}
}

func TestFormatStringVulnerability(t *testing.T) {
	code := `
void handler(char *input) {
    printf(input);
}
`
	findings := scanC(code)
	f := findByRule(findings, "BATOU-CAST-002")
	if f == nil {
		t.Error("expected format string vulnerability finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestFormatStringLiteralSafe(t *testing.T) {
	code := `
void handler(char *input) {
    printf("%s\n", input);
}
`
	findings := scanC(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-CAST-002" {
			t.Errorf("should not flag printf with literal format: %s", f.Title)
		}
	}
}

func TestSystemVariable(t *testing.T) {
	code := `
void handler(char *cmd) {
    system(cmd);
}
`
	findings := scanC(code)
	f := findByRule(findings, "BATOU-CAST-003")
	if f == nil {
		t.Error("expected command injection finding for system()")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestSystemLiteralSafe(t *testing.T) {
	code := `
void handler() {
    system("ls -la");
}
`
	findings := scanC(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-CAST-003" {
			t.Errorf("should not flag system with literal: %s", f.Title)
		}
	}
}

func TestPopenVariable(t *testing.T) {
	code := `
void handler(char *cmd) {
    FILE *fp = popen(cmd, "r");
}
`
	findings := scanC(code)
	f := findByRule(findings, "BATOU-CAST-003")
	if f == nil {
		t.Error("expected command injection finding for popen()")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestCPP(t *testing.T) {
	code := `
#include <cstdlib>
void handler(char *cmd) {
    system(cmd);
}
`
	tree := ast.Parse([]byte(code), rules.LangCPP)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.cpp",
		Content:  code,
		Language: rules.LangCPP,
		Tree:     tree,
	}
	a := &CASTAnalyzer{}
	findings := a.Scan(ctx)
	f := findByRule(findings, "BATOU-CAST-003")
	if f == nil {
		t.Error("expected finding for C++ system()")
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.c",
		Content:  "void f() { system(x); }",
		Language: rules.LangC,
		Tree:     nil,
	}
	a := &CASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings with nil tree")
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.py",
		Content:  "system(x)",
		Language: rules.LangPython,
	}
	a := &CASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

// TestFormatStringConstIdentifier covers the common false-positive shapes seen
// in real C codebases (Redis, vendored Lua, hdr_histogram): the format
// argument is a macro identifier, a const local pointing at a literal, or a
// ternary between two literals. None of these are CWE-134.
func TestFormatStringConstIdentifier(t *testing.T) {
	// Hardcoded literal — must NOT fire.
	literalCode := `
void handler(int x) {
    printf("hello %d\n", x);
}
`
	if got := countByRule(scanC(literalCode), "BATOU-CAST-002"); got != 0 {
		t.Errorf("printf with literal format should not fire, got %d findings", got)
	}

	// User-controlled format — must fire. We deliberately use a name that
	// does not match the const-format heuristics (no fmt/format/_str/ALL_CAPS).
	taintedCode := `
void handler(char *input, int x) {
    printf(input, x);
}
`
	if got := countByRule(scanC(taintedCode), "BATOU-CAST-002"); got != 1 {
		t.Errorf("printf with non-const variable format should fire once, got %d", got)
	}

	// ALL_CAPS macro identifier (e.g. LUA_NUMBER_FMT, CLUSTER_MANAGER_INVALID_HOST_ARG).
	macroCode := `
#define LUA_NUMBER_FMT "%.14g"
void handler(double d) {
    printf(LUA_NUMBER_FMT, d);
    fprintf(stderr, CLUSTER_MANAGER_INVALID_HOST_ARG);
}
`
	if got := countByRule(scanC(macroCode), "BATOU-CAST-002"); got != 0 {
		t.Errorf("printf/fprintf with ALL_CAPS macro format should not fire, got %d findings", got)
	}

	// Lowercase const-format names (format_str, head_format, line_format,
	// ascii_logo, branch, fmt) — Redis/Lua/hdr_histogram FPs.
	constNameCode := `
void handler(char *str, int len, int significant_figures, FILE *stream,
             double value, double percentile, long total_count,
             double inverted_percentile, char *buf, char *ascii_logo) {
    const char *format_str = "%s%d%s";
    const char *head_format = "%s\n";
    const char *line_format = "%f\n";
    const char *fmt = "%g";
    const char *branch = " (%c) ";
    snprintf(str, len, format_str, "x", significant_figures, "y");
    fprintf(stream, head_format, "Value");
    fprintf(stream, line_format, value, percentile, total_count, inverted_percentile);
    printf(fmt, value);
    printf(branch, 'a');
    snprintf(buf, 1024, ascii_logo, "v");
}
`
	if got := countByRule(scanC(constNameCode), "BATOU-CAST-002"); got != 0 {
		t.Errorf("printf-family with const-named format identifier should not fire, got %d findings", got)
	}

	// Ternary between two string literals (server.c:6290 pattern).
	ternaryCode := `
void handler(int cnt, char *buf, int buflen) {
    snprintf(buf + buflen, 1024, (cnt == 0) ? "%s=%llu" : ",%s=%llu", "k", 1ULL);
}
`
	if got := countByRule(scanC(ternaryCode), "BATOU-CAST-002"); got != 0 {
		t.Errorf("snprintf with ternary-of-literals format should not fire, got %d findings", got)
	}

	// Non-const variable name that is NOT in the allowlist — should still fire.
	nonConstCode := `
void handler(char *attacker_controlled) {
    printf(attacker_controlled);
}
`
	if got := countByRule(scanC(nonConstCode), "BATOU-CAST-002"); got != 1 {
		t.Errorf("printf with attacker_controlled variable should fire once, got %d", got)
	}
}

// TestTaintedSizeWrite covers CWE-787: a memory-copy intrinsic whose length
// argument is a caller-controlled function parameter writing into a fixed-size
// stack buffer.
func TestTaintedSizeWrite(t *testing.T) {
	// Canonical probe: n is a parameter, b is a fixed buffer -> CWE-787.
	vuln := `
#include <string.h>
void f(int n, char *src) {
    char b[64];
    memcpy(b, src, n);
}
`
	f := findByRule(scanC(vuln), "BATOU-CAST-004")
	if f == nil {
		t.Fatal("expected CWE-787 finding for memcpy with parameter-controlled size")
	}
	if f.CWEID != "CWE-787" {
		t.Errorf("expected CWE-787, got %s", f.CWEID)
	}

	// memmove variant.
	if findByRule(scanC(`
#include <string.h>
void g(unsigned len, char *p) {
    char dst[128];
    memmove(dst, p, len);
}
`), "BATOU-CAST-004") == nil {
		t.Error("expected CWE-787 finding for memmove with parameter-controlled size")
	}
}

// TestTaintedSizeWriteSafe covers the FP boundaries: a literal/sizeof size, a
// non-parameter local size, or a non-fixed destination must NOT fire.
func TestTaintedSizeWriteSafe(t *testing.T) {
	cases := map[string]string{
		"literal size is bounded": `
#include <string.h>
void f(char *src) {
    char b[64];
    memcpy(b, src, 64);
}
`,
		"sizeof size is bounded": `
#include <string.h>
void f(char *src) {
    char b[64];
    memcpy(b, src, sizeof(b));
}
`,
		"local non-parameter size": `
#include <string.h>
#include <stdlib.h>
void f(char *src) {
    char b[64];
    int n = atoi("10");
    memcpy(b, src, n);
}
`,
		"destination is not a fixed buffer": `
#include <string.h>
void f(int n, char *src, char *heapdst) {
    memcpy(heapdst, src, n);
}
`,
	}
	for name, code := range cases {
		if f := findByRule(scanC(code), "BATOU-CAST-004"); f != nil {
			t.Errorf("%s: should NOT fire CWE-787, got %q", name, f.Title)
		}
	}
}

// TestTaintedSizeWriteBoundsGuardSuppressed reproduces the real-world Redis FP
// shape (t_stream.c:2383): a memcpy whose parameter-controlled length is
// constrained by an early-exit size check ONE LINE ABOVE. The copy is bounded,
// so CWE-787 must NOT fire. This is the regression test for the bounds-guard
// recogniser (cast_bounds_guard.go).
func TestTaintedSizeWriteBoundsGuardSuppressed(t *testing.T) {
	cases := map[string]string{
		// Redis t_stream.c streamGenericParseIDOrReply shape.
		"sizeof-1 guard above memcpy": `
#include <string.h>
int parse(int strict, const char *o, int olen) {
    char buf[128];
    if (olen > sizeof(buf)-1) return -1;
    memcpy(buf, o, olen);
    return 0;
}
`,
		// Redis redis-check-aof.c PATH_MAX shape (guard a few lines above).
		"PATH_MAX guard above memcpy": `
#include <string.h>
#include <limits.h>
int check(int len, const char *filepath) {
    char temp[PATH_MAX];
    if (len > PATH_MAX) {
        return -1;
    }
    /* glibc dirname may modify its argument. */
    memcpy(temp, filepath, len);
    return 0;
}
`,
		// Redis cluster_asm.c CLUSTER_NAMELEN equality guard.
		"!= NAMELEN const guard above memcpy": `
#include <string.h>
#define CLUSTER_NAMELEN 40
int loadtask(int plen, const char *parts, char *dest) {
    char source[CLUSTER_NAMELEN];
    if (plen != CLUSTER_NAMELEN) return -1;
    memcpy(source, parts, plen);
    return 0;
}
`,
		// Guard with a goto rejection (Redis idiom).
		"goto-rejection size guard above memcpy": `
#include <string.h>
int f(int n, const char *src) {
    char b[64];
    if (n >= sizeof(b)) goto fail;
    memcpy(b, src, n);
    return 0;
fail:
    return -1;
}
`,
	}
	for name, code := range cases {
		if f := findByRule(scanC(code), "BATOU-CAST-004"); f != nil {
			t.Errorf("%s: bounds-guarded copy should NOT fire CWE-787, got %q at line %d",
				name, f.Title, f.LineNumber)
		}
	}
}

// TestTaintedSizeWriteUnguardedStillFires proves the bounds-guard recogniser
// TIGHTENS rather than DISABLES: a memcpy with no size guard, or one whose only
// preceding check is unrelated (a NULL-check, or a length check on a DIFFERENT
// variable, or a guard too far above), must STILL fire CWE-787.
func TestTaintedSizeWriteUnguardedStillFires(t *testing.T) {
	cases := map[string]string{
		// No guard at all — the canonical TP.
		"no guard": `
#include <string.h>
void f(int n, char *src) {
    char b[64];
    memcpy(b, src, n);
}
`,
		// Preceding check is a NULL-check, not a size comparison (Redis
		// cluster_legacy.c:488 shape — this must keep firing).
		"null-check is not a size guard": `
#include <string.h>
#include <stdlib.h>
void f(int n, char *src) {
    char b[64];
    if (src == NULL) return;
    memcpy(b, src, n);
}
`,
		// Size guard constrains a DIFFERENT variable than the copy size.
		"size guard on unrelated variable": `
#include <string.h>
void f(int n, int other, char *src) {
    char b[64];
    if (other > sizeof(b)-1) return;
    memcpy(b, src, n);
}
`,
		// Guard exists but is far above the copy (outside the lookback window) —
		// an unrelated earlier check that must not silence this copy.
		"size guard too far above": `
#include <string.h>
void f(int n, char *src, char *src2) {
    char b[64];
    if (n > sizeof(b)-1) return;
    int a1 = 1;
    int a2 = 2;
    int a3 = 3;
    int a4 = 4;
    int a5 = 5;
    int a6 = 6;
    int a7 = 7;
    int a8 = 8;
    int a9 = 9;
    memcpy(b, src2, n);
}
`,
	}
	for name, code := range cases {
		if findByRule(scanC(code), "BATOU-CAST-004") == nil {
			t.Errorf("%s: should STILL fire CWE-787 (recogniser must tighten, not disable)", name)
		}
	}
}

// TestAllocOverflow covers CWE-190: an allocation whose size multiplies two
// non-constant operands and can wrap.
func TestAllocOverflow(t *testing.T) {
	vuln := `
#include <stdlib.h>
void *h(int a, int b) {
    return malloc(a * b);
}
`
	f := findByRule(scanC(vuln), "BATOU-CAST-005")
	if f == nil {
		t.Fatal("expected CWE-190 finding for malloc(a * b)")
	}
	if f.CWEID != "CWE-190" {
		t.Errorf("expected CWE-190, got %s", f.CWEID)
	}

	// calloc per-element size and realloc size are also covered. left-shift too.
	for _, code := range []string{
		`#include <stdlib.h>
void *h(int a, int b) { return alloca(a * b); }`,
		`#include <stdlib.h>
void *h(int a, int b) { return malloc(a << b); }`,
	} {
		if findByRule(scanC(code), "BATOU-CAST-005") == nil {
			t.Errorf("expected CWE-190 finding for: %s", code)
		}
	}
}

// TestAllocOverflowSafe covers the FP boundaries: a constant factor
// (var * sizeof(T), var * 16) bounds the product and must NOT fire.
func TestAllocOverflowSafe(t *testing.T) {
	cases := map[string]string{
		"var times sizeof": `
#include <stdlib.h>
void *h(int n) { return malloc(n * sizeof(int)); }
`,
		"var times constant": `
#include <stdlib.h>
void *h(int n) { return malloc(n * 16); }
`,
		"single variable size": `
#include <stdlib.h>
void *h(int n) { return malloc(n); }
`,
		"constant times constant": `
#include <stdlib.h>
void *h(void) { return malloc(8 * 16); }
`,
	}
	for name, code := range cases {
		if f := findByRule(scanC(code), "BATOU-CAST-005"); f != nil {
			t.Errorf("%s: should NOT fire CWE-190, got %q", name, f.Title)
		}
	}
}

func TestLineNumbers(t *testing.T) {
	code := `
/* comment */
void handler(char *input) {
    printf(input);
}
`
	findings := scanC(code)
	f := findByRule(findings, "BATOU-CAST-002")
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.LineNumber != 4 {
		t.Errorf("expected line 4, got %d", f.LineNumber)
	}
}

// ---- Stage-1 UAF / double-free (CAST-006/007) ----

func scanCpp(code string) []rules.Finding {
	tree := ast.Parse([]byte(code), rules.LangCPP)
	ctx := &rules.ScanContext{FilePath: "/app/handler.cpp", Content: code, Language: rules.LangCPP, Tree: tree}
	return (&CASTAnalyzer{}).Scan(ctx)
}

func hasRule(fs []rules.Finding, id string) bool { return findByRule(fs, id) != nil }

func TestCAST_DoubleFree_Fires(t *testing.T) {
	code := "void f() {\n\tchar *p = malloc(8);\n\tfree(p);\n\tfree(p);\n}\n"
	if !hasRule(scanC(code), "BATOU-CAST-006") {
		t.Error("expected BATOU-CAST-006 (double free)")
	}
}

func TestCAST_UAF_Deref_Fires(t *testing.T) {
	// field deref after free. (Returning a freed pointer is a bare identifier,
	// not a deref, so the return-value form is intentionally not asserted here;
	// the call-arg form is covered by TestCAST_UAF_CallArg_Fires.)
	if !hasRule(scanC("void f(struct s *p) {\n\tfree(p);\n\tp->n = 1;\n}\n"), "BATOU-CAST-007") {
		t.Error("expected BATOU-CAST-007 on p->n after free")
	}
}

func TestCAST_UAF_CallArg_Fires(t *testing.T) {
	if !hasRule(scanC("void f(char *p, char *s) {\n\tfree(p);\n\tstrcpy(p, s);\n}\n"), "BATOU-CAST-007") {
		t.Error("expected BATOU-CAST-007 on strcpy(p,...) after free")
	}
}

func TestCAST_UAF_Cpp_Delete_Fires(t *testing.T) {
	if !hasRule(scanCpp("void f(T *p) {\n\tdelete p;\n\tp->run();\n}\n"), "BATOU-CAST-007") {
		t.Error("expected BATOU-CAST-007 on p->run() after delete")
	}
	if !hasRule(scanCpp("void f(int *a) {\n\tdelete[] a;\n\ta[0] = 1;\n}\n"), "BATOU-CAST-007") {
		t.Error("expected BATOU-CAST-007 on a[0] after delete[]")
	}
}

// FP must-not-fire cases (the gate proof).
func TestCAST_UAF_NoFP_ConditionalFreeReturn(t *testing.T) {
	code := "void f(char *p, int err) {\n\tif (err) {\n\t\tfree(p);\n\t\treturn;\n\t}\n\tuse(p);\n}\n"
	if hasRule(scanC(code), "BATOU-CAST-007") || hasRule(scanC(code), "BATOU-CAST-006") {
		t.Error("conditional free+return then use must NOT fire (branch rule)")
	}
}

func TestCAST_UAF_NoFP_ReassignClears(t *testing.T) {
	code := "void f(char *p) {\n\tfree(p);\n\tp = malloc(16);\n\tuse(p);\n}\n"
	if hasRule(scanC(code), "BATOU-CAST-007") {
		t.Error("free then reassign then use must NOT fire (reassign clears)")
	}
}

func TestCAST_UAF_NoFP_DistinctObjects(t *testing.T) {
	code := "void f(char *a, char *b) {\n\tfree(a);\n\tfree(b);\n}\n"
	if hasRule(scanC(code), "BATOU-CAST-006") {
		t.Error("freeing two distinct objects must NOT be a double free")
	}
}

func TestCAST_UAF_NoFP_FreeWrapperArg(t *testing.T) {
	// Passing the freed pointer to a cleanup helper / freeReplyObject is not a UAF.
	code := "void f(char *p) {\n\tfree(p);\n\tfreeReplyObject(p);\n}\n"
	if hasRule(scanC(code), "BATOU-CAST-007") {
		t.Error("passing freed pointer to a cleanup call must NOT fire")
	}
}

// --- BATOU-CAST-008: unchecked privilege-drop return value (CWE-252) ---

func TestCAST_PrivDrop_UncheckedFires(t *testing.T) {
	// A bare setuid()/setgid() statement discards the return — the drop may
	// silently fail and leave the process running as root (CWE-252).
	code := "void drop(uid_t u, gid_t g) {\n\tsetgid(g);\n\tsetuid(u);\n}\n"
	findings := scanC(code)
	if countByRule(findings, "BATOU-CAST-008") != 2 {
		t.Errorf("expected 2 unchecked priv-drop findings, got %d", countByRule(findings, "BATOU-CAST-008"))
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
	if f := findByRule(findings, "BATOU-CAST-008"); f != nil && f.CWEID != "CWE-252" {
		t.Errorf("expected CWE-252, got %s", f.CWEID)
	}
}

func TestCAST_PrivDrop_AllVariantsFire(t *testing.T) {
	// Every member of the set*id family is in scope when its return is discarded.
	code := "void d(void) {\n" +
		"\tsetuid(0);\n\tsetgid(0);\n\tseteuid(0);\n\tsetegid(0);\n" +
		"\tsetreuid(0,0);\n\tsetregid(0,0);\n\tsetresuid(0,0,0);\n\tsetresgid(0,0,0);\n}\n"
	if got := countByRule(scanC(code), "BATOU-CAST-008"); got != 8 {
		t.Errorf("expected 8 priv-drop findings (one per set*id), got %d", got)
	}
}

func TestCAST_PrivDrop_NoFP_IfGuarded(t *testing.T) {
	// `if (setuid(u) != 0)` consumes the return — the failure IS handled.
	code := "void drop(uid_t u) {\n\tif (setuid(u) != 0) {\n\t\t_exit(1);\n\t}\n}\n"
	if hasRule(scanC(code), "BATOU-CAST-008") {
		t.Error("if-guarded setuid() return must NOT fire (return is checked)")
	}
}

func TestCAST_PrivDrop_NoFP_Assigned(t *testing.T) {
	// `int r = setuid(u);` captures the return for a later check — not discarded.
	code := "void drop(uid_t u) {\n\tint r = setuid(u);\n\tif (r) _exit(1);\n}\n"
	if hasRule(scanC(code), "BATOU-CAST-008") {
		t.Error("assigned setuid() return must NOT fire (return is captured)")
	}
}

func TestCAST_PrivDrop_NoFP_Returned(t *testing.T) {
	// `return setuid(u);` propagates the status to the caller — not discarded.
	code := "int drop(uid_t u) {\n\treturn setuid(u);\n}\n"
	if hasRule(scanC(code), "BATOU-CAST-008") {
		t.Error("returned setuid() result must NOT fire (status propagated)")
	}
}

func TestCAST_PrivDrop_NoFP_UnrelatedSetCall(t *testing.T) {
	// A bare call to an unrelated set* / app function must never be confused
	// with a privilege-drop syscall — the family list is exact.
	code := "void f(int x) {\n\tsetsockopt(x, 0, 0, 0, 0);\n\tsettings_apply(x);\n}\n"
	if hasRule(scanC(code), "BATOU-CAST-008") {
		t.Error("non-priv-drop set* call must NOT fire (exact family match)")
	}
}
