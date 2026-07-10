package main

import (
	"go/types"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"golang.org/x/tools/go/packages"
)

func TestParseFreeFuncPattern(t *testing.T) {
	cases := []struct {
		name        string
		pattern     string
		wantOK      bool
		wantAlias   string
		wantFunc    string
	}{
		{
			name:      "simple",
			pattern:   `http\.ServeContent\(`,
			wantOK:    true,
			wantAlias: "http",
			wantFunc:  "ServeContent",
		},
		{
			name:      "with whitespace allowance",
			pattern:   `http\.ServeContent\s*\(`,
			wantOK:    true,
			wantAlias: "http",
			wantFunc:  "ServeContent",
		},
		{
			name:    "method receiver — rejected",
			pattern: `\.Query\(`,
			wantOK:  false,
		},
		{
			name:    "alternation — rejected (can't pick one)",
			pattern: `webhook\.NewRequest\s*\(|notifier\.Deliver\s*\(`,
			wantOK:  false,
		},
		{
			name:    "sub-package selector — rejected",
			pattern: `crypto\.tls\.Listen\(`,
			wantOK:  false,
		},
		{
			name:    "lowercase function — rejected",
			pattern: `os\.exec\.command\(`,
			wantOK:  false,
		},
		{
			name:      "variadic-ish pattern",
			pattern:   `exec\.CommandContext\(`,
			wantOK:    true,
			wantAlias: "exec",
			wantFunc:  "CommandContext",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alias, fn, ok := parseFreeFuncPattern(tc.pattern)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if alias != tc.wantAlias {
				t.Errorf("alias = %q, want %q", alias, tc.wantAlias)
			}
			if fn != tc.wantFunc {
				t.Errorf("funcName = %q, want %q", fn, tc.wantFunc)
			}
		})
	}
}

func TestNonTaintableReason(t *testing.T) {
	// Load a small set of stdlib packages once to resolve real Go types.
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedTypes}
	pkgs, err := packages.Load(cfg, "time", "context", "os", "sync", "net/http")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	pkgByPath := map[string]*packages.Package{}
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			t.Fatalf("load errors for %s: %v", p.PkgPath, p.Errors)
		}
		pkgByPath[p.PkgPath] = p
	}

	// Helper: look up a named type in a package by name.
	lookupNamed := func(pkgPath, name string) types.Type {
		obj := pkgByPath[pkgPath].Types.Scope().Lookup(name)
		if obj == nil {
			t.Fatalf("type %s.%s not found", pkgPath, name)
		}
		return obj.Type()
	}

	// Helper: look up a function in a package and return param i's type.
	lookupParam := func(pkgPath, funcName string, idx int) types.Type {
		obj := pkgByPath[pkgPath].Types.Scope().Lookup(funcName)
		if obj == nil {
			t.Fatalf("func %s.%s not found", pkgPath, funcName)
		}
		fn := obj.(*types.Func)
		sig := fn.Type().(*types.Signature)
		return sig.Params().At(idx).Type()
	}

	// types.Universe.Lookup gives us the built-in error/string/bool.
	errorType := types.Universe.Lookup("error").Type()

	tests := []struct {
		name    string
		t       types.Type
		wantBad bool
	}{
		{
			name:    "time.Time — not taintable",
			t:       lookupNamed("time", "Time"),
			wantBad: true,
		},
		{
			name:    "*time.Time — not taintable",
			t:       types.NewPointer(lookupNamed("time", "Time")),
			wantBad: true,
		},
		{
			name:    "context.Context — not taintable",
			t:       lookupNamed("context", "Context"),
			wantBad: true,
		},
		{
			name:    "*os.File — not taintable",
			t:       types.NewPointer(lookupNamed("os", "File")),
			wantBad: true,
		},
		{
			name:    "*sync.Mutex — not taintable",
			t:       types.NewPointer(lookupNamed("sync", "Mutex")),
			wantBad: true,
		},
		{
			name:    "*sync.WaitGroup — not taintable",
			t:       types.NewPointer(lookupNamed("sync", "WaitGroup")),
			wantBad: true,
		},
		{
			name:    "error — not taintable",
			t:       errorType,
			wantBad: true,
		},
		{
			name:    "int — not taintable",
			t:       types.Typ[types.Int],
			wantBad: true,
		},
		{
			name:    "bool — not taintable",
			t:       types.Typ[types.Bool],
			wantBad: true,
		},
		{
			name:    "float64 — not taintable",
			t:       types.Typ[types.Float64],
			wantBad: true,
		},
		{
			name:    "chan string — not taintable",
			t:       types.NewChan(types.SendRecv, types.Typ[types.String]),
			wantBad: true,
		},
		{
			name:    "func() — not taintable",
			t:       types.NewSignatureType(nil, nil, nil, nil, nil, false),
			wantBad: true,
		},
		{
			name:    "string — taintable",
			t:       types.Typ[types.String],
			wantBad: false,
		},
		{
			name:    "[]byte — taintable",
			t:       types.NewSlice(types.Typ[types.Byte]),
			wantBad: false,
		},
		{
			name:    "[]string — taintable (variadic args)",
			t:       types.NewSlice(types.Typ[types.String]),
			wantBad: false,
		},
		{
			// io.ReadSeeker is an interface other than error; we treat it
			// as opaquely taintable rather than flag it.
			name:    "io.ReadSeeker — assumed taintable (multi-method interface)",
			t:       lookupParam("net/http", "ServeContent", 4),
			wantBad: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason, bad := nonTaintableReason(tc.t)
			if bad != tc.wantBad {
				t.Fatalf("nonTaintableReason(%s) bad=%v reason=%q, wantBad=%v", tc.t, bad, reason, tc.wantBad)
			}
			if bad && reason == "" {
				t.Errorf("flagged as bad but reason is empty")
			}
		})
	}
}

// fakeSink builds a minimal SinkDef whose only relevant field for the
// validator is DangerousArgs. Other fields (Pattern, Severity, etc.) are
// left zero — they're not inspected by validateSink.
func fakeSink(id string, dangerousArgIndex int) taint.SinkDef {
	return taint.SinkDef{
		ID:            id,
		DangerousArgs: []int{dangerousArgIndex},
	}
}

// fakeSinkMulti is fakeSink with multiple dangerous arg positions.
func fakeSinkMulti(id string, dangerousArgs ...int) taint.SinkDef {
	return taint.SinkDef{
		ID:            id,
		DangerousArgs: append([]int(nil), dangerousArgs...),
	}
}

// TestValidateSink_ServeContent_Modtime — a regression for the bug that
// motivated this auditor: http.ServeContent's 4th argument is modtime
// (time.Time) and was incorrectly listed as a DangerousArg. The catalog
// entry has since been removed, but the validator must still flag the
// position if it ever reappears.
func TestValidateSink_ServeContent_Modtime(t *testing.T) {
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedTypes}
	pkgs, err := packages.Load(cfg, "net/http")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	if len(pkgs) != 1 || len(pkgs[0].Errors) != 0 {
		t.Fatalf("unexpected load result: %+v", pkgs)
	}

	violations, ok := validateSink(pkgs[0], "ServeContent", fakeSink("test.servecontent", 3), "net/http")
	if !ok {
		t.Fatalf("validateSink could not find net/http.ServeContent")
	}
	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1: %+v", len(violations), violations)
	}
	v := violations[0]
	if v.ParamName != "modtime" {
		t.Errorf("ParamName = %q, want %q", v.ParamName, "modtime")
	}
	if v.ArgIndex != 3 {
		t.Errorf("ArgIndex = %d, want 3", v.ArgIndex)
	}
}

// TestValidateSink_VariadicOK — exec.Command(name, arg...) — index 2 is
// past the formal parameter count but valid because the last param is
// variadic of `string`. Must NOT flag.
func TestValidateSink_VariadicOK(t *testing.T) {
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedTypes}
	pkgs, err := packages.Load(cfg, "os/exec")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	violations, ok := validateSink(pkgs[0], "Command", fakeSinkMulti("test.command", 0, 1, 2, 5), "os/exec")
	if !ok {
		t.Fatalf("validateSink could not find os/exec.Command")
	}
	if len(violations) != 0 {
		t.Errorf("got %d violations for variadic Command, want 0: %+v", len(violations), violations)
	}
}
