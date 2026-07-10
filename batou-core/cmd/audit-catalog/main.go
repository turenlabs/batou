// Command audit-catalog mechanically validates the Go taint sink catalog.
//
// For every SinkDef whose Pattern resolves to a stdlib free function
// (e.g. `http\.ServeContent\s*\(`), the auditor:
//   - looks up the real Go signature via go/types,
//   - examines each parameter named in DangerousArgs, and
//   - flags positions whose parameter type cannot plausibly carry
//     user-controlled string data (time.Time, context.Context, *os.File,
//     numeric, error, chan, func, etc.).
//
// The auditor only validates Go stdlib entries this round. Receiver methods
// (Pattern starts with `\.`), multi-pattern alternations, and third-party
// packages (Pattern uses a non-stdlib alias) are skipped — see scope notes
// in batou-core/CLAUDE.md.
//
// Exit codes:
//
//	0  — no violations
//	1  — at least one DangerousArgs position references a non-taintable
//	     parameter type
//	2  — internal error (failed to load stdlib packages, etc.)
package main

import (
	"flag"
	"fmt"
	"go/types"
	"os"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// stdlibAliases maps the leading identifier used in a sink Pattern
// (the package alias as Go developers conventionally write it) to the
// canonical stdlib import path. Only unambiguous mappings live here;
// ambiguous aliases (e.g. "template" → text/template vs html/template,
// "rand" → math/rand vs crypto/rand) are intentionally absent so the
// auditor skips them rather than flag false positives.
var stdlibAliases = map[string]string{
	"bufio":    "bufio",
	"bytes":    "bytes",
	"context":  "context",
	"exec":     "os/exec",
	"filepath": "path/filepath",
	"fmt":      "fmt",
	"http":     "net/http",
	"io":       "io",
	"ioutil":   "io/ioutil",
	"log":      "log",
	"net":      "net",
	"os":       "os",
	"path":     "path",
	"slog":     "log/slog",
	"smtp":     "net/smtp",
	"sql":      "database/sql",
	"strconv":  "strconv",
	"strings":  "strings",
	"syscall":  "syscall",
	"url":      "net/url",
	"xml":      "encoding/xml",
}

// patternFreeFunc matches a sink Pattern that targets a free function in
// a single package alias. We deliberately reject:
//   - alternations  (contains `|`)
//   - leading `\.`  (receiver method — would need ObjectType resolution)
//   - sub-package selectors (e.g. `crypto\.tls\.Listen`)
//
// The pattern shape accepted is `^<alias>\.<Func>(?:\\s\*)?\\(`.
var patternFreeFunc = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9_]*)\\\.([A-Z][A-Za-z0-9_]*)(?:\\s\*)?\\\(\s*$`)

// Violation is one DangerousArgs position that references a parameter
// type which cannot carry tainted string data.
type Violation struct {
	SinkID     string
	ImportPath string
	FuncName   string
	ArgIndex   int
	ParamName  string
	ParamType  string
	Reason     string
}

func main() {
	verbose := flag.Bool("v", false, "verbose output (show resolved + skipped entries too)")
	flag.Parse()

	sinks := taint.SinksForLanguage(rules.LangGo)
	if len(sinks) == 0 {
		fmt.Fprintln(os.Stderr, "audit-catalog: no Go sinks registered — taint/languages import missing?")
		os.Exit(2)
	}

	// First pass: parse every Pattern, group resolvable sinks by import path
	// so we can load each stdlib package once.
	type resolved struct {
		sink     taint.SinkDef
		funcName string
	}
	byPkg := map[string][]resolved{}
	skipped := 0
	for _, s := range sinks {
		alias, funcName, ok := parseFreeFuncPattern(s.Pattern)
		if !ok {
			skipped++
			if *verbose {
				fmt.Fprintf(os.Stderr, "skip (pattern shape): %s — %q\n", s.ID, s.Pattern)
			}
			continue
		}
		importPath, ok := stdlibAliases[alias]
		if !ok {
			skipped++
			if *verbose {
				fmt.Fprintf(os.Stderr, "skip (non-stdlib alias %q): %s\n", alias, s.ID)
			}
			continue
		}
		// Only consider the entry if ObjectType is empty — non-empty
		// ObjectType means the sink is a method on a typed receiver and
		// DangerousArgs are scored against the method signature, which
		// we don't try to resolve mechanically here.
		if s.ObjectType != "" {
			skipped++
			if *verbose {
				fmt.Fprintf(os.Stderr, "skip (ObjectType=%q): %s\n", s.ObjectType, s.ID)
			}
			continue
		}
		byPkg[importPath] = append(byPkg[importPath], resolved{sink: s, funcName: funcName})
	}

	if len(byPkg) == 0 {
		fmt.Fprintln(os.Stderr, "audit-catalog: nothing resolvable to validate")
		os.Exit(2)
	}

	// Load all needed stdlib packages in one packages.Load call.
	patterns := make([]string, 0, len(byPkg))
	for p := range byPkg {
		patterns = append(patterns, p)
	}
	sort.Strings(patterns)

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo,
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-catalog: packages.Load: %v\n", err)
		os.Exit(2)
	}
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			for _, e := range p.Errors {
				fmt.Fprintf(os.Stderr, "audit-catalog: load %s: %v\n", p.PkgPath, e)
			}
			os.Exit(2)
		}
	}
	pkgByPath := map[string]*packages.Package{}
	for _, p := range pkgs {
		pkgByPath[p.PkgPath] = p
	}

	// Second pass: for each (pkg, sink) pair, look up the function and
	// validate every DangerousArgs position.
	var violations []Violation
	validated := 0
	for importPath, entries := range byPkg {
		pkg, ok := pkgByPath[importPath]
		if !ok || pkg.Types == nil {
			fmt.Fprintf(os.Stderr, "audit-catalog: failed to resolve package %q\n", importPath)
			os.Exit(2)
		}
		for _, e := range entries {
			vs, ok := validateSink(pkg, e.funcName, e.sink, importPath)
			if !ok {
				if *verbose {
					fmt.Fprintf(os.Stderr, "skip (func %s.%s not found or not a function): %s\n", importPath, e.funcName, e.sink.ID)
				}
				continue
			}
			validated++
			violations = append(violations, vs...)
		}
	}

	// Stable ordering for deterministic output.
	sort.Slice(violations, func(i, j int) bool {
		if violations[i].SinkID != violations[j].SinkID {
			return violations[i].SinkID < violations[j].SinkID
		}
		return violations[i].ArgIndex < violations[j].ArgIndex
	})

	fmt.Printf("audit-catalog: %d sinks validated, %d skipped (non-stdlib / non-free-func / method receivers)\n", validated, skipped)
	if len(violations) == 0 {
		fmt.Println("audit-catalog: OK — no DangerousArgs position references a non-taintable parameter type")
		return
	}

	fmt.Printf("\naudit-catalog: %d violation(s):\n", len(violations))
	for _, v := range violations {
		fmt.Printf("  %s\n", formatViolation(v))
	}
	os.Exit(1)
}

// parseFreeFuncPattern attempts to extract (alias, funcName) from a sink
// Pattern targeting a free function. Returns ok=false for any pattern
// shape the auditor cannot mechanically validate.
func parseFreeFuncPattern(pattern string) (alias, funcName string, ok bool) {
	if strings.Contains(pattern, "|") {
		return "", "", false
	}
	m := patternFreeFunc.FindStringSubmatch(pattern)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// validateSink looks up funcName in pkg, walks DangerousArgs, and emits
// one Violation per non-taintable position. Returns ok=false if the
// function isn't present in the package (catalog drift).
func validateSink(pkg *packages.Package, funcName string, sink taint.SinkDef, importPath string) ([]Violation, bool) {
	obj := pkg.Types.Scope().Lookup(funcName)
	if obj == nil {
		return nil, false
	}
	fn, ok := obj.(*types.Func)
	if !ok {
		return nil, false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return nil, false
	}
	params := sig.Params()
	isVariadic := sig.Variadic()
	lastIdx := params.Len() - 1

	var out []Violation
	for _, idx := range sink.DangerousArgs {
		if idx < 0 {
			// -1 = "any" — can't validate positionally.
			continue
		}
		// Resolve the effective parameter for index `idx`.
		// For a variadic function `f(a, b, vs ...string)`, indices past
		// the declared parameter count correspond to additional spread
		// arguments and share the element type of the variadic slice.
		var effective *types.Var
		var effectiveType types.Type
		switch {
		case idx < params.Len() && (!isVariadic || idx != lastIdx):
			effective = params.At(idx)
			effectiveType = effective.Type()
		case isVariadic && idx >= lastIdx:
			effective = params.At(lastIdx)
			slice, ok := effective.Type().(*types.Slice)
			if !ok {
				// Should not happen for a real variadic signature.
				out = append(out, Violation{
					SinkID:     sink.ID,
					ImportPath: importPath,
					FuncName:   funcName,
					ArgIndex:   idx,
					ParamType:  effective.Type().String(),
					Reason:     "variadic parameter is not a slice type (impossible?)",
				})
				continue
			}
			effectiveType = slice.Elem()
		default:
			// Non-variadic function and idx past the end — definitely wrong.
			out = append(out, Violation{
				SinkID:     sink.ID,
				ImportPath: importPath,
				FuncName:   funcName,
				ArgIndex:   idx,
				ParamType:  "<out-of-range>",
				Reason:     fmt.Sprintf("DangerousArgs index %d is past the signature's last parameter (%d)", idx, lastIdx),
			})
			continue
		}
		if reason, bad := nonTaintableReason(effectiveType); bad {
			v := Violation{
				SinkID:     sink.ID,
				ImportPath: importPath,
				FuncName:   funcName,
				ArgIndex:   idx,
				ParamType:  effectiveType.String(),
				Reason:     reason,
			}
			if effective != nil {
				v.ParamName = effective.Name()
			}
			out = append(out, v)
		}
	}
	return out, true
}

// nonTaintableReason classifies a parameter type. Returns a human reason
// if the type cannot plausibly carry user-controlled string data, or
// "" + false otherwise. Conservative by design: any type we're unsure
// about (interfaces, structs other than time.Time, named string types,
// []byte, etc.) is treated as taintable.
func nonTaintableReason(t types.Type) (string, bool) {
	// Strip a single pointer level — *time.Time is just as non-taintable
	// as time.Time.
	if ptr, ok := t.(*types.Pointer); ok {
		if r, bad := nonTaintableNamedReason(ptr.Elem()); bad {
			return r, true
		}
		// Fall through: *something we don't know about → assume taintable.
		return "", false
	}

	// Channels can't carry inline taint.
	if _, ok := t.(*types.Chan); ok {
		return "channel parameter cannot carry user-controlled string data", true
	}

	// Function-typed parameters: same.
	if _, ok := t.(*types.Signature); ok {
		return "function-typed parameter cannot carry user-controlled string data", true
	}

	// Basic types other than string / []byte. Numerics, bool, etc.
	if b, ok := t.(*types.Basic); ok {
		switch b.Kind() {
		case types.String, types.UntypedString:
			return "", false
		// All other basic kinds (numerics, bool, complex, uintptr…)
		// cannot carry a user-controlled string.
		default:
			return fmt.Sprintf("basic type %q cannot carry user-controlled string data", b.Name()), true
		}
	}

	// Slices: []byte is taintable, []rune is taintable, everything else
	// (e.g. []time.Time) is suspicious but we conservatively allow it.
	if sl, ok := t.(*types.Slice); ok {
		if b, ok := sl.Elem().(*types.Basic); ok {
			// types.Byte == types.Uint8 and types.Rune == types.Int32,
			// so the explicit String / Uint8 / Int32 cases cover
			// []byte, []rune, and []string.
			switch b.Kind() {
			case types.String, types.Uint8, types.Int32:
				return "", false
			}
		}
		return "", false
	}

	// Named types: defer to nonTaintableNamedReason.
	if r, bad := nonTaintableNamedReason(t); bad {
		return r, true
	}

	return "", false
}

// nonTaintableNamedReason handles named stdlib types that cannot carry
// tainted string data even though they are not basic types. Currently:
// time.Time, context.Context, error, os.File, sync.Mutex/WaitGroup.
func nonTaintableNamedReason(t types.Type) (string, bool) {
	named, ok := t.(*types.Named)
	if !ok {
		// Interfaces are *types.Interface in newer Go; the built-in
		// `error` is a *types.Interface whose underlying is itself.
		if iface, ok := t.(*types.Interface); ok && iface.NumMethods() == 1 {
			m := iface.Method(0)
			if m.Name() == "Error" {
				return "error parameter cannot carry user-controlled string data", true
			}
		}
		return "", false
	}
	obj := named.Obj()
	if obj == nil {
		return "", false
	}
	// Predeclared types (e.g. the built-in `error`) live in the universe
	// scope and have no package. They still need to be classified.
	if obj.Pkg() == nil {
		if obj.Name() == "error" {
			return "error parameter cannot carry user-controlled string data", true
		}
		return "", false
	}
	qualified := obj.Pkg().Path() + "." + obj.Name()
	switch qualified {
	case "time.Time":
		return "time.Time cannot carry user-controlled string data", true
	case "context.Context":
		return "context.Context is not a string sink input", true
	case "os.File":
		return "*os.File is an open handle, not user input", true
	case "sync.Mutex", "sync.RWMutex", "sync.WaitGroup", "sync.Once":
		return "sync primitive cannot carry user-controlled string data", true
	}
	return "", false
}

func formatViolation(v Violation) string {
	return fmt.Sprintf("%-40s %s.%s arg[%d] %s (%s) — %s",
		v.SinkID, v.ImportPath, v.FuncName, v.ArgIndex, v.ParamName, v.ParamType, v.Reason)
}
