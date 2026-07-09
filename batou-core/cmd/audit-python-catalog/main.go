// Command audit-python-catalog mechanically validates the Python taint
// sink catalog. It mirrors batou-core/cmd/audit-catalog (the Go auditor),
// but adapts the strategy to Python — which has no compile-time type
// checker — by combining:
//
//   - subprocess introspection of `inspect.signature()` against a real
//     Python interpreter (stdlib only, no pip installs), and
//   - a curated allowlist of "non-taintable" parameter shapes inferred
//     from annotations and parameter names.
//
// For every SinkDef whose Pattern resolves to a free function in a
// known stdlib module (e.g. `pickle\.loads\(`, `os\.system\(`,
// `subprocess\.\w+\(`), the auditor:
//   - resolves the function's real signature via `python3 -c "..."`,
//   - examines each parameter named in DangerousArgs, and
//   - flags positions whose annotation or name strongly indicates a
//     non-taintable type (int, bool, time.struct_time, socket.socket,
//     threading.Lock, etc.).
//
// # Conservative-pass philosophy
//
// Python annotations on stdlib functions are sparse — most older
// stdlib functions are C-implemented and inspect.signature() either
// returns no annotation or fails outright. The auditor therefore:
//
//   - **passes** any position where no annotation is present and the
//     parameter name does not appear in the curated suspicious-name
//     list (better to miss a real bug than yell at a real catalog),
//   - **passes** any sink whose function cannot be imported (third
//     party module not installed, dynamic name, etc.),
//   - **passes** if Python isn't available at all (prints a warning
//     and exits 0 so CI doesn't break on Python-less machines).
//
// Sinks are only flagged when:
//
//   - the DangerousArgs index is past the parameter count of a
//     non-variadic function (a real catalog bug), or
//   - the parameter at that index has an annotation matching the
//     non-taintable allowlist, or
//   - the parameter name matches the curated suspicious-name list
//     (e.g. `bufsize`, `timeout`, `mode`, `port`, `lock`).
//
// Exit codes:
//
//	0  — no violations, or Python unavailable
//	1  — at least one DangerousArgs position references a non-taintable
//	     parameter
//	2  — internal error (catalog empty, subprocess failure other than
//	     "no python")
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// nonTaintableAnnotations maps an annotation string (as printed by
// inspect.Parameter.annotation via `getattr(p.annotation, "__qualname__",
// repr(p.annotation))`) to the human reason the parameter cannot carry
// user-controlled string data.
//
// We only list types whose values are NEVER reasonable taint carriers
// (numerics, booleans, sockets, locks, time tuples). Strings, bytes,
// `Any`, `object`, and unannotated parameters are conservatively
// considered taintable.
var nonTaintableAnnotations = map[string]string{
	"int":                 "int parameter cannot carry user-controlled string data",
	"float":               "float parameter cannot carry user-controlled string data",
	"bool":                "bool parameter cannot carry user-controlled string data",
	"complex":             "complex parameter cannot carry user-controlled string data",
	"range":               "range parameter cannot carry user-controlled string data",
	"time.struct_time":    "time.struct_time cannot carry user-controlled string data",
	"datetime.datetime":   "datetime.datetime is an object, not a string sink input",
	"datetime.date":       "datetime.date is an object, not a string sink input",
	"datetime.time":       "datetime.time is an object, not a string sink input",
	"datetime.timedelta":  "datetime.timedelta is an object, not a string sink input",
	"socket.socket":       "socket.socket is an open handle, not user input",
	"ssl.SSLContext":      "ssl.SSLContext is a config object, not user input",
	"threading.Lock":      "threading.Lock cannot carry user-controlled string data",
	"threading.RLock":     "threading.RLock cannot carry user-controlled string data",
	"threading.Event":     "threading.Event cannot carry user-controlled string data",
	"threading.Semaphore": "threading.Semaphore cannot carry user-controlled string data",
	"_thread.lock":        "_thread.lock cannot carry user-controlled string data",
}

// suspiciousParamNames maps a parameter name to a human reason. These
// names appear in stdlib signatures where annotations are absent but
// the documented semantics strongly imply a non-taintable type.
//
// Conservative by design — we only list names whose meaning is
// unambiguous across stdlib usage. Generic names like `value`, `arg`,
// `data` are intentionally absent.
var suspiciousParamNames = map[string]string{
	"bufsize": "bufsize is an integer buffer size, not user input",
	"timeout": "timeout is a numeric/None, not user input",
	"port":    "port is an integer, not a string sink input",
	"backlog": "backlog is an integer, not user input",
	"fileno":  "fileno is an integer file descriptor, not user input",
	"fd":      "fd is an integer file descriptor, not user input",
	"sock":    "sock is a socket handle, not user input",
	"socket":  "socket is an open handle, not user input",
	"lock":    "lock is a synchronization primitive, not user input",
	"flags":   "flags is a numeric bitmask, not user input",
	"signum":  "signum is an integer signal number, not user input",
	"closefd": "closefd is a bool, not user input",
	"opener":  "opener is a callable, not user input",
	"check":   "check is a bool, not user input",
	"shell":   "shell is a bool, not user input",
}

// stdlibAllowedModules lists Python modules the auditor is willing to
// import in its subprocess. We exclude anything that would require a
// pip install — the auditor must run on a vanilla Python install.
var stdlibAllowedModules = map[string]bool{
	"os":                    true,
	"os.path":               true,
	"subprocess":            true,
	"pickle":                true,
	"shelve":                true,
	"marshal":               true,
	"shutil":                true,
	"pty":                   true,
	"socket":                true,
	"ssl":                   true,
	"http.client":           true,
	"urllib":                true,
	"urllib.parse":          true,
	"urllib.request":        true,
	"sqlite3":               true,
	"tarfile":               true,
	"zipfile":               true,
	"xml.etree.ElementTree": true,
	"xml.dom.minidom":       true,
	"xml.dom.pulldom":       true,
	"xml.sax":               true,
	"xmlrpc.client":         true,
	"xmlrpc.server":         true,
	"json":                  true,
	"yaml":                  false, // third-party, must NOT be required
	"time":                  true,
	"datetime":              true,
	"threading":             true,
	"hashlib":               true,
	"hmac":                  true,
	"base64":                true,
	"codecs":                true,
	"functools":             true,
	"re":                    true,
	"csv":                   true,
	"tempfile":              true,
	"io":                    true,
	"builtins":              true, // for `eval`, `exec`, `open`, ...
}

// patternFreeFunc matches a sink Pattern that targets a free function
// in a single module, possibly with a dotted sub-module (`os.path.join`).
//
// Accepted shape: `^<module>(\.<sub>)*\.<func>(?:\s*)?\(`
// with optional trailing `\s*\(` (regex-escaped backslash sequences).
//
// Rejected:
//   - leading `\.` (method receiver — like the Go auditor)
//   - alternations (`|`)
var patternFreeFunc = regexp.MustCompile(
	`^([a-zA-Z_][a-zA-Z0-9_]*(?:\\\.[a-zA-Z_][a-zA-Z0-9_]*)*)\\\.([a-zA-Z_][a-zA-Z0-9_]*)(?:\\s\*)?\\\(\s*$`,
)

// patternBareBuiltin matches a sink Pattern targeting a bare builtin
// name like `eval\(` / `exec\(` / `open\(`. We resolve these against
// the `builtins` module.
var patternBareBuiltin = regexp.MustCompile(
	`^([a-zA-Z_][a-zA-Z0-9_]*)(?:\\s\*)?\\\(\s*$`,
)

// bareBuiltins is the curated set of Python builtins the catalog may
// reference with a no-module pattern. Restricting this set keeps the
// auditor honest — we don't want to match a name that's actually a
// method on a user-defined class.
var bareBuiltins = map[string]bool{
	"eval":       true,
	"exec":       true,
	"compile":    true,
	"open":       true,
	"input":      true,
	"__import__": true,
	"getattr":    true,
	"setattr":    true,
}

// Violation is one DangerousArgs position that references a parameter
// our heuristics flag as non-taintable.
type Violation struct {
	SinkID    string
	Module    string
	FuncName  string
	ArgIndex  int
	ParamName string
	ParamType string
	Reason    string
}

// SigQuery is one request to the Python subprocess to resolve a
// `module.dotted.func` signature.
type SigQuery struct {
	Key    string `json:"key"`    // unique opaque key — we use the sink ID
	Module string `json:"module"` // import path, e.g. "subprocess"
	Func   string `json:"func"`   // attribute path inside the module, e.g. "run"
}

// SigResult is one entry returned by the subprocess: either a resolved
// signature or an Error explaining why we couldn't resolve it.
type SigResult struct {
	Key      string     `json:"key"`
	Error    string     `json:"error,omitempty"`
	Params   []SigParam `json:"params,omitempty"`
	Variadic bool       `json:"variadic,omitempty"`
}

// SigParam mirrors inspect.Parameter — name, optional annotation as a
// printable string, and the parameter "kind" (POSITIONAL_ONLY,
// POSITIONAL_OR_KEYWORD, VAR_POSITIONAL, KEYWORD_ONLY, VAR_KEYWORD).
type SigParam struct {
	Name       string `json:"name"`
	Annotation string `json:"annotation,omitempty"` // "" if no annotation
	Kind       string `json:"kind"`
}

func main() {
	verbose := flag.Bool("v", false, "verbose output (show resolved + skipped entries)")
	pythonPath := flag.String("python", "python3", "Python interpreter to use")
	flag.Parse()

	sinks := taint.SinksForLanguage(rules.LangPython)
	if len(sinks) == 0 {
		fmt.Fprintln(os.Stderr, "audit-python-catalog: no Python sinks registered — taint/languages import missing?")
		os.Exit(2)
	}

	// First pass: figure out which sinks we can possibly validate.
	type candidate struct {
		sink   taint.SinkDef
		module string
		fn     string
	}
	var candidates []candidate
	skipped := 0
	for _, s := range sinks {
		if s.ObjectType != "" {
			skipped++
			if *verbose {
				fmt.Fprintf(os.Stderr, "skip (ObjectType=%q): %s\n", s.ObjectType, s.ID)
			}
			continue
		}
		mod, fn, ok := parseFreeFuncPattern(s.Pattern)
		if !ok {
			skipped++
			if *verbose {
				fmt.Fprintf(os.Stderr, "skip (pattern shape): %s — %q\n", s.ID, s.Pattern)
			}
			continue
		}
		// Restrict to modules we will actually import (stdlib-only).
		// If RequireModule is set on the sink and points to a known
		// third-party module, skip — we don't pip-install.
		if !stdlibAllowedModules[mod] {
			skipped++
			if *verbose {
				fmt.Fprintf(os.Stderr, "skip (non-stdlib module %q): %s\n", mod, s.ID)
			}
			continue
		}
		candidates = append(candidates, candidate{sink: s, module: mod, fn: fn})
	}

	if len(candidates) == 0 {
		fmt.Printf("audit-python-catalog: 0 sinks validated, %d skipped (no resolvable stdlib free functions)\n", skipped)
		return
	}

	// Resolve signatures in a single Python subprocess.
	queries := make([]SigQuery, 0, len(candidates))
	for _, c := range candidates {
		queries = append(queries, SigQuery{Key: c.sink.ID, Module: c.module, Func: c.fn})
	}
	results, err := resolveSignatures(*pythonPath, queries)
	if err != nil {
		// If python is missing, gracefully exit 0 so CI on a
		// python-less machine doesn't break.
		if isPythonMissingErr(err) {
			fmt.Fprintf(os.Stderr, "audit-python-catalog: python interpreter %q not found — skipping (this is non-fatal)\n", *pythonPath)
			return
		}
		fmt.Fprintf(os.Stderr, "audit-python-catalog: subprocess failed: %v\n", err)
		os.Exit(2)
	}
	resByKey := map[string]SigResult{}
	for _, r := range results {
		resByKey[r.Key] = r
	}

	// Second pass: validate each resolved candidate.
	var violations []Violation
	validated := 0
	unresolved := 0
	for _, c := range candidates {
		r, ok := resByKey[c.sink.ID]
		if !ok || r.Error != "" {
			unresolved++
			if *verbose {
				reason := "(no result)"
				if ok {
					reason = r.Error
				}
				fmt.Fprintf(os.Stderr, "skip (unresolved %s.%s): %s — %s\n", c.module, c.fn, c.sink.ID, reason)
			}
			continue
		}
		validated++
		vs := validateSink(c.sink, c.module, c.fn, r)
		violations = append(violations, vs...)
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].SinkID != violations[j].SinkID {
			return violations[i].SinkID < violations[j].SinkID
		}
		return violations[i].ArgIndex < violations[j].ArgIndex
	})

	fmt.Printf("audit-python-catalog: %d sinks validated, %d unresolved, %d skipped\n",
		validated, unresolved, skipped)
	if len(violations) == 0 {
		fmt.Println("audit-python-catalog: OK — no DangerousArgs position references a non-taintable parameter")
		return
	}
	fmt.Printf("\naudit-python-catalog: %d violation(s):\n", len(violations))
	for _, v := range violations {
		fmt.Printf("  %s\n", formatViolation(v))
	}
	os.Exit(1)
}

// parseFreeFuncPattern extracts (module, funcName) from a regex sink
// Pattern. The regex syntax in the catalog uses `\.` and `\(` to
// escape literal `.` and `(`. We accept dotted module paths like
// `os.path.join` because Python free functions live under sub-modules.
//
// Bare-builtin patterns (e.g. `eval\(`) are resolved against the
// `builtins` module, but only for the curated `bareBuiltins` set —
// otherwise we'd accidentally validate method names matched by a
// no-receiver regex like `\.search_st\s*\(` against random builtins.
func parseFreeFuncPattern(pattern string) (module, funcName string, ok bool) {
	if strings.Contains(pattern, "|") {
		return "", "", false
	}
	if m := patternFreeFunc.FindStringSubmatch(pattern); m != nil {
		module = strings.ReplaceAll(m[1], `\.`, ".")
		funcName = m[2]
		return module, funcName, true
	}
	if m := patternBareBuiltin.FindStringSubmatch(pattern); m != nil {
		name := m[1]
		if bareBuiltins[name] {
			return "builtins", name, true
		}
	}
	return "", "", false
}

// validateSink walks the SinkDef.DangerousArgs and emits one Violation
// per non-taintable position, given a resolved Python signature.
func validateSink(sink taint.SinkDef, module, fn string, r SigResult) []Violation {
	var out []Violation
	// Compute effective parameter count and variadic-element index.
	// inspect.Parameter kinds we care about:
	//   POSITIONAL_ONLY, POSITIONAL_OR_KEYWORD  — count toward index
	//   VAR_POSITIONAL                          — `*args`, swallows tail
	//   KEYWORD_ONLY, VAR_KEYWORD               — not addressable by index
	positional := []SigParam{}
	varArgsIdx := -1
	for _, p := range r.Params {
		// Skip self/cls for safety even though our caller filters
		// receiver methods (ObjectType != "" / Pattern starts with \.)
		if (p.Name == "self" || p.Name == "cls") &&
			(p.Kind == "POSITIONAL_ONLY" || p.Kind == "POSITIONAL_OR_KEYWORD") {
			continue
		}
		switch p.Kind {
		case "POSITIONAL_ONLY", "POSITIONAL_OR_KEYWORD":
			positional = append(positional, p)
		case "VAR_POSITIONAL":
			varArgsIdx = len(positional)
			positional = append(positional, p)
		}
	}
	hasVariadic := varArgsIdx >= 0
	lastIdx := len(positional) - 1

	for _, idx := range sink.DangerousArgs {
		if idx < 0 {
			continue
		}
		var p SigParam
		switch {
		case idx <= lastIdx && (!hasVariadic || idx != varArgsIdx):
			p = positional[idx]
		case hasVariadic && idx >= varArgsIdx:
			// Spread args share the *args param's element shape; we
			// can only check its annotation and name.
			p = positional[varArgsIdx]
		default:
			// Out of range: this is a real catalog bug.
			out = append(out, Violation{
				SinkID:   sink.ID,
				Module:   module,
				FuncName: fn,
				ArgIndex: idx,
				Reason:   fmt.Sprintf("DangerousArgs index %d is past the last positional parameter (%d)", idx, lastIdx),
			})
			continue
		}
		if reason, bad := nonTaintableReason(p); bad {
			out = append(out, Violation{
				SinkID:    sink.ID,
				Module:    module,
				FuncName:  fn,
				ArgIndex:  idx,
				ParamName: p.Name,
				ParamType: p.Annotation,
				Reason:    reason,
			})
		}
	}
	return out
}

// nonTaintableReason classifies a parameter. Returns a human reason if
// the parameter cannot plausibly carry user-controlled string data,
// or "" + false otherwise. Conservative: missing annotation + neutral
// name -> taintable.
func nonTaintableReason(p SigParam) (string, bool) {
	// 1. Annotation match (when present).
	if p.Annotation != "" {
		if reason, ok := nonTaintableAnnotations[p.Annotation]; ok {
			return reason, true
		}
	}
	// 2. Name-based heuristic.
	if reason, ok := suspiciousParamNames[p.Name]; ok {
		return reason, true
	}
	return "", false
}

// resolveSignatures spawns one python3 process that introspects every
// queried (module, func) and returns a JSON array of SigResult, one
// per query. The subprocess never imports anything outside
// `stdlibAllowedModules` — it must work on a vanilla Python install.
func resolveSignatures(python string, queries []SigQuery) ([]SigResult, error) {
	queriesJSON, err := json.Marshal(queries)
	if err != nil {
		return nil, fmt.Errorf("marshal queries: %w", err)
	}
	cmd := exec.Command(python, "-c", pythonResolverScript)
	cmd.Stdin = bytes.NewReader(queriesJSON)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Distinguish "python not found" from other errors. The runtime
		// wraps the lookup error in either *exec.Error or *fs.PathError
		// depending on Go version / platform; errors.Is(fs.ErrNotExist)
		// catches both.
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			return nil, &pythonMissingErr{wrapped: err}
		}
		return nil, fmt.Errorf("python subprocess: %w (stderr=%q)", err, stderr.String())
	}
	var results []SigResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		return nil, fmt.Errorf("unmarshal results: %w (stdout=%q stderr=%q)", err, stdout.String(), stderr.String())
	}
	return results, nil
}

// pythonResolverScript is the script that runs in the subprocess. It
// reads JSON queries on stdin and writes a JSON array on stdout. It
// must stay self-contained — no pip-installed imports. Functions with
// no introspectable signature (C built-ins) report Error="no signature
// available" and the auditor treats that as "conservatively pass".
const pythonResolverScript = `
import sys, json, inspect, importlib

queries = json.loads(sys.stdin.read())
out = []
for q in queries:
    key, module, func = q['key'], q['module'], q['func']
    try:
        mod = importlib.import_module(module)
    except Exception as e:
        out.append({'key': key, 'error': 'import failed: ' + repr(e)})
        continue
    try:
        target = mod
        for part in func.split('.'):
            target = getattr(target, part)
    except Exception as e:
        out.append({'key': key, 'error': 'attr failed: ' + repr(e)})
        continue
    try:
        sig = inspect.signature(target)
    except (ValueError, TypeError) as e:
        out.append({'key': key, 'error': 'signature failed: ' + repr(e)})
        continue
    params = []
    variadic = False
    for name, p in sig.parameters.items():
        kind = str(p.kind)
        ann = ''
        if p.annotation is not inspect._empty:
            a = p.annotation
            if hasattr(a, '__module__') and hasattr(a, '__qualname__'):
                mod_name = getattr(a, '__module__', '')
                qual = getattr(a, '__qualname__', '')
                if mod_name in ('builtins', ''):
                    ann = qual
                else:
                    ann = mod_name + '.' + qual
            else:
                ann = str(a)
        params.append({'name': name, 'annotation': ann, 'kind': kind})
        if p.kind is inspect.Parameter.VAR_POSITIONAL:
            variadic = True
    out.append({'key': key, 'params': params, 'variadic': variadic})

json.dump(out, sys.stdout)
`

// pythonMissingErr signals that the python interpreter could not be
// launched (typical case: no `python3` on $PATH).
type pythonMissingErr struct{ wrapped error }

func (e *pythonMissingErr) Error() string {
	return "python interpreter not found: " + e.wrapped.Error()
}
func (e *pythonMissingErr) Unwrap() error { return e.wrapped }

func isPythonMissingErr(err error) bool {
	_, ok := err.(*pythonMissingErr)
	return ok
}

func formatViolation(v Violation) string {
	t := v.ParamType
	if t == "" {
		t = "<unannotated>"
	}
	pn := v.ParamName
	if pn == "" {
		pn = "<unnamed>"
	}
	return fmt.Sprintf("%-40s %s.%s arg[%d] %s (%s) — %s",
		v.SinkID, v.Module, v.FuncName, v.ArgIndex, pn, t, v.Reason)
}
