package main

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
)

// TestParseFreeFuncPattern covers the regex that decides which sink
// Patterns the auditor is willing to validate.
func TestParseFreeFuncPattern(t *testing.T) {
	cases := []struct {
		name       string
		pattern    string
		wantOK     bool
		wantModule string
		wantFunc   string
	}{
		{
			name:       "simple free function",
			pattern:    `os\.system\(`,
			wantOK:     true,
			wantModule: "os",
			wantFunc:   "system",
		},
		{
			name:       "free function with whitespace allowance",
			pattern:    `pickle\.loads\s*\(`,
			wantOK:     true,
			wantModule: "pickle",
			wantFunc:   "loads",
		},
		{
			name:       "dotted module path",
			pattern:    `os\.path\.join\(`,
			wantOK:     true,
			wantModule: "os.path",
			wantFunc:   "join",
		},
		{
			name:       "deeper dotted module path",
			pattern:    `urllib\.request\.urlopen\(`,
			wantOK:     true,
			wantModule: "urllib.request",
			wantFunc:   "urlopen",
		},
		{
			name:    "method receiver — rejected",
			pattern: `\.execute\(`,
			wantOK:  false,
		},
		{
			name:    "alternation — rejected",
			pattern: `subprocess\.run\(|subprocess\.call\(`,
			wantOK:  false,
		},
		{
			name:    "wildcard method — rejected (regex escape mismatch)",
			pattern: `subprocess\.\w+\(`,
			wantOK:  false,
		},
		{
			name:       "bare builtin via builtins prefix",
			pattern:    `builtins\.eval\(`,
			wantOK:     true,
			wantModule: "builtins",
			wantFunc:   "eval",
		},
		{
			name:       "bare eval resolved to builtins",
			pattern:    `eval\(`,
			wantOK:     true,
			wantModule: "builtins",
			wantFunc:   "eval",
		},
		{
			name:       "bare exec resolved to builtins",
			pattern:    `exec\(`,
			wantOK:     true,
			wantModule: "builtins",
			wantFunc:   "exec",
		},
		{
			name:       "bare open resolved to builtins",
			pattern:    `open\(`,
			wantOK:     true,
			wantModule: "builtins",
			wantFunc:   "open",
		},
		{
			name:    "bare non-builtin name rejected (could be anything)",
			pattern: `redirect\(`,
			wantOK:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mod, fn, ok := parseFreeFuncPattern(tc.pattern)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (mod=%q fn=%q)", ok, tc.wantOK, mod, fn)
			}
			if !ok {
				return
			}
			if mod != tc.wantModule {
				t.Errorf("module = %q, want %q", mod, tc.wantModule)
			}
			if fn != tc.wantFunc {
				t.Errorf("func = %q, want %q", fn, tc.wantFunc)
			}
		})
	}
}

// TestNonTaintableReason covers the annotation + name heuristic. We
// build SigParams synthetically — no python3 subprocess required.
func TestNonTaintableReason(t *testing.T) {
	cases := []struct {
		name    string
		p       SigParam
		wantBad bool
	}{
		{
			name:    "string annotation — taintable",
			p:       SigParam{Name: "cmd", Annotation: "str", Kind: "POSITIONAL_OR_KEYWORD"},
			wantBad: false,
		},
		{
			name:    "int annotation — non-taintable",
			p:       SigParam{Name: "x", Annotation: "int", Kind: "POSITIONAL_OR_KEYWORD"},
			wantBad: true,
		},
		{
			name:    "bool annotation — non-taintable",
			p:       SigParam{Name: "shell", Annotation: "bool", Kind: "POSITIONAL_OR_KEYWORD"},
			wantBad: true,
		},
		{
			name:    "float annotation — non-taintable",
			p:       SigParam{Name: "t", Annotation: "float", Kind: "POSITIONAL_OR_KEYWORD"},
			wantBad: true,
		},
		{
			name:    "time.struct_time — non-taintable",
			p:       SigParam{Name: "t", Annotation: "time.struct_time", Kind: "POSITIONAL_OR_KEYWORD"},
			wantBad: true,
		},
		{
			name:    "socket.socket — non-taintable",
			p:       SigParam{Name: "s", Annotation: "socket.socket", Kind: "POSITIONAL_OR_KEYWORD"},
			wantBad: true,
		},
		{
			name:    "threading.Lock — non-taintable",
			p:       SigParam{Name: "l", Annotation: "threading.Lock", Kind: "POSITIONAL_OR_KEYWORD"},
			wantBad: true,
		},
		{
			name:    "unannotated, neutral name — pass",
			p:       SigParam{Name: "data", Annotation: "", Kind: "POSITIONAL_OR_KEYWORD"},
			wantBad: false,
		},
		{
			name:    "unannotated, suspicious name `bufsize` — flagged",
			p:       SigParam{Name: "bufsize", Annotation: "", Kind: "POSITIONAL_OR_KEYWORD"},
			wantBad: true,
		},
		{
			name:    "unannotated, suspicious name `timeout` — flagged",
			p:       SigParam{Name: "timeout", Annotation: "", Kind: "POSITIONAL_OR_KEYWORD"},
			wantBad: true,
		},
		{
			name:    "unannotated, suspicious name `port` — flagged",
			p:       SigParam{Name: "port", Annotation: "", Kind: "POSITIONAL_OR_KEYWORD"},
			wantBad: true,
		},
		{
			name:    "unannotated string-like name `url` — pass",
			p:       SigParam{Name: "url", Annotation: "", Kind: "POSITIONAL_OR_KEYWORD"},
			wantBad: false,
		},
		{
			name:    "Any annotation — pass (could be anything)",
			p:       SigParam{Name: "obj", Annotation: "typing.Any", Kind: "POSITIONAL_OR_KEYWORD"},
			wantBad: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, bad := nonTaintableReason(tc.p)
			if bad != tc.wantBad {
				t.Fatalf("bad=%v reason=%q, want bad=%v", bad, reason, tc.wantBad)
			}
			if bad && reason == "" {
				t.Errorf("flagged as bad but reason is empty")
			}
		})
	}
}

// fakeSink builds a SinkDef with only the fields validateSink reads.
func fakeSink(id string, args ...int) taint.SinkDef {
	return taint.SinkDef{
		ID:            id,
		DangerousArgs: append([]int(nil), args...),
	}
}

// TestValidateSink_OutOfRange — DangerousArgs index past the last
// positional parameter on a non-variadic function is a real catalog
// bug and must always be flagged.
func TestValidateSink_OutOfRange(t *testing.T) {
	// Synthetic signature for `pickle.loads(data, *, fix_imports=True, ...)`.
	// Only one positional parameter; DangerousArgs:[0] = OK, [1] = bug.
	sig := SigResult{
		Key: "test.loads",
		Params: []SigParam{
			{Name: "data", Annotation: "", Kind: "POSITIONAL_ONLY"},
			{Name: "fix_imports", Annotation: "", Kind: "KEYWORD_ONLY"},
		},
	}
	// Good case
	good := validateSink(fakeSink("test.loads", 0), "pickle", "loads", sig)
	if len(good) != 0 {
		t.Errorf("expected 0 violations for in-range arg, got %d: %+v", len(good), good)
	}
	// Out-of-range case
	bad := validateSink(fakeSink("test.loads_bad", 1), "pickle", "loads", sig)
	if len(bad) != 1 {
		t.Fatalf("expected 1 violation for out-of-range arg, got %d: %+v", len(bad), bad)
	}
	if bad[0].ArgIndex != 1 {
		t.Errorf("ArgIndex = %d, want 1", bad[0].ArgIndex)
	}
	if bad[0].Reason == "" {
		t.Error("Reason is empty")
	}
}

// TestValidateSink_VariadicOK — `os.path.join(a, *p)` index 0, 1, 2
// must all be accepted; index 2 falls into the *p spread.
func TestValidateSink_VariadicOK(t *testing.T) {
	sig := SigResult{
		Key: "test.join",
		Params: []SigParam{
			{Name: "a", Annotation: "", Kind: "POSITIONAL_OR_KEYWORD"},
			{Name: "p", Annotation: "", Kind: "VAR_POSITIONAL"},
		},
		Variadic: true,
	}
	out := validateSink(fakeSink("test.join", 0, 1, 5), "os.path", "join", sig)
	if len(out) != 0 {
		t.Errorf("expected 0 violations for variadic spread, got %d: %+v", len(out), out)
	}
}

// TestValidateSink_AnnotationFlagged — int-annotated parameter at a
// dangerous position should be flagged.
func TestValidateSink_AnnotationFlagged(t *testing.T) {
	sig := SigResult{
		Key: "test.foo",
		Params: []SigParam{
			{Name: "name", Annotation: "str", Kind: "POSITIONAL_OR_KEYWORD"},
			{Name: "bufsize", Annotation: "int", Kind: "POSITIONAL_OR_KEYWORD"},
		},
	}
	out := validateSink(fakeSink("test.foo", 0, 1), "some.mod", "foo", sig)
	if len(out) != 1 {
		t.Fatalf("expected 1 violation, got %d: %+v", len(out), out)
	}
	if out[0].ArgIndex != 1 {
		t.Errorf("ArgIndex = %d, want 1", out[0].ArgIndex)
	}
	if out[0].ParamName != "bufsize" {
		t.Errorf("ParamName = %q, want bufsize", out[0].ParamName)
	}
}

// TestValidateSink_NameFlagged — unannotated parameter whose NAME is
// in the suspicious list should be flagged.
func TestValidateSink_NameFlagged(t *testing.T) {
	sig := SigResult{
		Key: "test.subprocess.run",
		Params: []SigParam{
			{Name: "args", Annotation: "", Kind: "POSITIONAL_OR_KEYWORD"},
			{Name: "timeout", Annotation: "", Kind: "POSITIONAL_OR_KEYWORD"},
		},
	}
	out := validateSink(fakeSink("test.subprocess.run", 1), "subprocess", "run", sig)
	if len(out) != 1 {
		t.Fatalf("expected 1 violation, got %d: %+v", len(out), out)
	}
	if out[0].ParamName != "timeout" {
		t.Errorf("ParamName = %q, want timeout", out[0].ParamName)
	}
}

// TestValidateSink_SkipsSelf — `self`/`cls` parameters should not
// count toward the positional index (defensive: callers should
// already have filtered receiver methods, but the helper must be
// safe if one slips through).
func TestValidateSink_SkipsSelf(t *testing.T) {
	sig := SigResult{
		Key: "test.foo",
		Params: []SigParam{
			{Name: "self", Annotation: "", Kind: "POSITIONAL_OR_KEYWORD"},
			{Name: "url", Annotation: "str", Kind: "POSITIONAL_OR_KEYWORD"},
		},
	}
	// DangerousArgs:[0] points at "url" (not "self") and "url" is taintable.
	out := validateSink(fakeSink("test.foo", 0), "x.y", "foo", sig)
	if len(out) != 0 {
		t.Errorf("expected 0 violations after self skip, got %d: %+v", len(out), out)
	}
}

// TestValidateSink_NegativeIndexSkipped — `-1` means "any" arg and
// can't be validated positionally; must NOT produce a violation.
func TestValidateSink_NegativeIndexSkipped(t *testing.T) {
	sig := SigResult{
		Key: "test.x",
		Params: []SigParam{
			{Name: "a", Annotation: "int", Kind: "POSITIONAL_OR_KEYWORD"},
		},
	}
	out := validateSink(fakeSink("test.x", -1), "x", "x", sig)
	if len(out) != 0 {
		t.Errorf("expected 0 violations for -1 arg, got %d: %+v", len(out), out)
	}
}

// TestStdlibAllowedModules — a smoke test that the curated module
// allowlist contains the modules used by stdlib Python sinks.
func TestStdlibAllowedModules(t *testing.T) {
	required := []string{"os", "subprocess", "pickle", "shutil", "builtins"}
	for _, m := range required {
		if !stdlibAllowedModules[m] {
			t.Errorf("module %q should be in stdlibAllowedModules", m)
		}
	}
	// Third-party modules must be explicitly NOT allowed.
	if stdlibAllowedModules["yaml"] {
		t.Errorf("yaml is third-party and must not be allowed")
	}
}
