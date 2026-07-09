// Package dirscan implements the `batou scan DIR` subcommand: walk a directory
// tree, run the hook-protocol scanner on each matching file, and emit one
// finding per line as JSON to stdout. Designed for ad-hoc audits and piping
// through jq/grep rather than for the Claude Code hook path.
package dirscan

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof" // Registers /debug/pprof/* handlers on http.DefaultServeMux when --pprof-http is enabled.
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"github.com/turenlabs/batou-core/graph"
	"github.com/turenlabs/batou-core/hook"
	"github.com/turenlabs/batou-core/reporter"
	"github.com/turenlabs/batou-core/scanner"
	"github.com/turenlabs/batou-rules/rules"
)

// Options configures a directory scan.
type Options struct {
	Root         string
	Exts         []string      // file extensions to scan (with leading "."); empty = all files batou can handle
	Exclude      []string      // directory names to skip (matched against each path component)
	Workers      int           // concurrent file scans; 0 = GOMAXPROCS
	FileDeadline time.Duration // per-file timeout; 0 = no deadline beyond the scanner's internal 10s
	Out          io.Writer     // stdout for JSONL findings
	ErrOut       io.Writer     // stderr for progress and errors

	// IncludeRegex enables emission of regex-tier (Layer-1) findings — i.e.
	// findings that no AST / taint / interprocedural layer confirmed. These
	// dominate the false-positive count on real codebases, so the default
	// (false) drops them and only emits data-flow-confirmed findings.
	//
	// IMPORTANT: secrets/crypto/misconfig findings are legitimately regex-only
	// (they can't be data-flow analyzed), so with the default IncludeRegex=false
	// you will NOT see `BATOU-SECRETS-*`, weak-crypto, or misconfig hits. Set
	// IncludeRegex=true (CLI: --with-regex) to surface them.
	//
	// Note on dedup: a regex finding that AST/taint/interproc confirmed on the
	// same line is replaced by the higher-tier winner during DeduplicateFindings
	// BEFORE this filter runs, so it survives IncludeRegex=false.
	IncludeRegex bool
	// RegexOnly keeps ONLY regex-tier findings. Useful for a secrets-and-crypto
	// pass or for debugging the regex layer. Mutually exclusive with
	// IncludeRegex. Default false.
	RegexOnly bool
	// MinConfidence drops findings whose ConfidenceScore is below this value.
	// 0 disables the filter. 0.7 keeps AST/interproc-confirmed plus
	// high-confidence taint findings and drops the rest.
	MinConfidence float64

	// CallgraphPath overrides the default .batou/callgraph.json location for
	// the persistent call graph (the file the scanner uses to track
	// interprocedural taint signatures across runs). Empty means "use the
	// default": .batou/callgraph.json relative to the current working
	// directory. Mutually exclusive with NoCallgraph.
	CallgraphPath string
	// NoCallgraph skips writing (and reading) the persistent call graph.
	// The graph is still built in-memory for interprocedural analysis during
	// the scan; only persistence is bypassed. Useful for one-shot CI scans
	// where leaving .batou/callgraph.json on disk would be noise.
	// Mutually exclusive with CallgraphPath.
	NoCallgraph bool

	// CPUProfile, if non-empty, writes a CPU profile to the given path. The
	// profile is started before file walking begins and stopped just before
	// Run returns, so it captures the entire scan including the cross-file
	// finalize pass. No-op when empty.
	CPUProfile string
	// MemProfile, if non-empty, writes a heap profile to the given path just
	// before Run returns. Uses pprof.Lookup("heap").WriteTo. No-op when empty.
	MemProfile string
	// PprofHTTP, if non-empty, starts a net/http/pprof server listening on
	// the given address (e.g. ":6060") before file walking begins. Useful
	// for sampling profiles mid-scan via:
	//   go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30
	// The server keeps running until the process exits. No-op when empty.
	PprofHTTP string

	// MaxPerCrossFileSink caps how many BATOU-INTERPROC-* findings share a
	// (leaf-sink-file, leaf-sink-line, rule_id) group before the (N+1)th
	// and beyond get RolledUp=true tagged. Default value is wired from
	// scanner.DefaultCrossFileSinkCap (currently 10). Set to 0 to disable
	// the marker (every flow surfaces equally). Negative means "use the
	// default". See scanner.MarkCrossFileSinkRollups for the semantics —
	// recall is preserved (every flow stays in the JSONL stream); only
	// the tag changes so downstream consumers can hide duplicates.
	MaxPerCrossFileSink int

	// FailOn selects the CI gating policy (CLI: --fail-on). It controls which
	// emitted findings count toward Stats.FailOnMatches — RunCLI exits 3 when
	// that count is nonzero. Accepted values (see the FailOn* constants):
	//   ""/"none"  — default; never gate (current behavior, Stats.FailOnMatches stays 0)
	//   "any"      — every emitted finding counts
	//   "blocking" — findings whose Finding.ShouldBlock() is true (risk_score >= 0.7)
	//   "critical" — findings with severity Critical
	//   "high"     — findings with severity High or Critical
	// The tier/confidence filters (IncludeRegex / RegexOnly / MinConfidence)
	// apply FIRST: only findings actually emitted (JSONL lines / SARIF results,
	// including cross-file ones) are evaluated against the policy. Unknown
	// values make RunStats return an error.
	FailOn string

	// SARIF switches the output format from streaming JSONL to a single
	// SARIF 2.1.0 document written to Out after the whole scan (including the
	// cross-file finalize pass) completes. SARIF is one JSON object containing
	// every result, so unlike JSONL it cannot be streamed per file — findings
	// are collected in memory and rendered once via reporter.ToSARIFJSON.
	// The same --with-regex / --regex-only / --min-confidence filters apply.
	SARIF bool

	// crossSink, when non-nil, redirects the cross-file/cross-language
	// interproc findings that finalizeCrossFileEdges would otherwise JSONL-emit
	// into this slice instead (used by SARIF mode to aggregate them with the
	// per-file findings). The pointer survives the by-value Options copies that
	// finalizeCrossFileEdges / emitCrossFileFindings receive, so every call
	// appends to the same underlying slice. nil in normal JSONL mode.
	crossSink *[]rules.Finding
}

// Accepted Options.FailOn / --fail-on policy values.
const (
	FailOnNone     = "none"     // never gate (default)
	FailOnAny      = "any"      // any emitted finding
	FailOnBlocking = "blocking" // findings that would block a write (Finding.ShouldBlock)
	FailOnCritical = "critical" // severity == Critical
	FailOnHigh     = "high"     // severity >= High
)

// Stats summarizes a completed scan for programmatic callers (RunStats).
type Stats struct {
	// FailOnMatches counts emitted findings (per-file and cross-file, after
	// the tier/confidence filters) that matched Options.FailOn. Always 0 when
	// FailOn is ""/"none".
	FailOnMatches int64
}

// normalizeFailOn validates and canonicalizes a FailOn policy value.
// "" is accepted as an alias for "none" so zero-value Options keep the
// historical no-gating behavior.
func normalizeFailOn(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", FailOnNone:
		return FailOnNone, nil
	case FailOnAny:
		return FailOnAny, nil
	case FailOnBlocking:
		return FailOnBlocking, nil
	case FailOnCritical:
		return FailOnCritical, nil
	case FailOnHigh:
		return FailOnHigh, nil
	default:
		return "", fmt.Errorf("invalid --fail-on value %q (want none, any, blocking, critical, or high)", v)
	}
}

// failOnMatch reports whether one emitted finding matches the (already
// normalized) policy. policy "none" / "" matches nothing.
func failOnMatch(policy string, f *rules.Finding) bool {
	switch policy {
	case FailOnAny:
		return true
	case FailOnBlocking:
		return f.ShouldBlock()
	case FailOnCritical:
		return f.Severity >= rules.Critical
	case FailOnHigh:
		return f.Severity >= rules.High
	default:
		return false
	}
}

// countFailOn counts the findings in fs matching the policy.
func countFailOn(policy string, fs []rules.Finding) int {
	if policy == "" || policy == FailOnNone {
		return 0
	}
	n := 0
	for i := range fs {
		if failOnMatch(policy, &fs[i]) {
			n++
		}
	}
	return n
}

// defaultExcludes lists directories we never want to scan. Kept short;
// users can extend via --exclude.
//
// .yarn covers Yarn 2+'s checked-in package-manager bundle (.yarn/releases/
// yarn-X.Y.Z.cjs is a multi-MB minified blob that triggers dozens of FPs).
// .pnpm matches PNPM's checked-in store. Both are the package-manager
// equivalent of node_modules and never contain the project's own code.
var defaultExcludes = []string{
	"node_modules", ".git", "vendor", "dist", "build", ".next",
	"__pycache__", ".venv", "venv", "target", ".mvn",
	".yarn", ".pnpm",
}

// defaultExts covers the languages Batou supports. If a caller wants the
// scanner to try every file regardless of extension, pass --ext "*".
var defaultExts = []string{
	".go", ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
	".java", ".kt", ".kts", ".rb", ".php", ".cs", ".rs", ".swift",
	".c", ".cpp", ".cc", ".h", ".hpp", ".pl", ".pm", ".t", ".cgi", ".lua",
	".groovy", ".zig", ".sh", ".bash", ".zsh",
}

// RunCLI parses args and runs a directory scan. Returns a shell exit code.
func RunCLI(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		extsFlag            string
		excludeFlag         string
		outputFlag          string
		workers             int
		timeoutMs           int
		quiet               bool
		withRegex           bool
		noRegex             bool
		regexOnly           bool
		minConfidence       float64
		callgraphPath       string
		noCallgraph         bool
		cpuProfile          string
		memProfile          string
		pprofHTTP           string
		maxPerCrossFileSink int
		sarifFlag           bool
		failOn              string
	)
	fs.StringVar(&extsFlag, "exts", "", "comma-separated file extensions (e.g. .go,.py). Empty uses the batou-supported default list. Pass '*' to scan all files.")
	fs.StringVar(&excludeFlag, "exclude", "", "comma-separated directory names to skip (extends the built-in list)")
	fs.StringVar(&outputFlag, "output", "", "write JSONL findings to this file instead of stdout")
	fs.IntVar(&workers, "workers", 0, "concurrent file scans (default GOMAXPROCS)")
	fs.IntVar(&timeoutMs, "timeout", 15000, "per-file deadline in milliseconds (0 = none)")
	fs.BoolVar(&quiet, "quiet", false, "suppress progress on stderr")
	fs.BoolVar(&withRegex, "with-regex", false, "include regex-tier (Layer-1) findings — turns on secrets/weak-crypto/misconfig hits and other Layer-1 findings that no AST/taint/interproc layer confirmed")
	fs.BoolVar(&noRegex, "no-regex", false, "(compat alias for the default; explicitly drops regex-tier findings) — matches the default behavior since 2026-05-13")
	fs.BoolVar(&regexOnly, "regex-only", false, "keep ONLY regex-tier findings (e.g. a secrets-and-crypto pass)")
	fs.Float64Var(&minConfidence, "min-confidence", 0, "drop findings with confidence_score below this value (0 = no filter; 0.7 keeps AST/interproc + high-confidence taint)")
	fs.StringVar(&callgraphPath, "callgraph", "", "explicit path for the persistent call graph (default: .batou/callgraph.json relative to cwd; pass --no-callgraph to skip persistence)")
	fs.BoolVar(&noCallgraph, "no-callgraph", false, "skip writing the persistent call graph — useful for one-shot CI scans where the on-disk graph would be noise (mutually exclusive with --callgraph)")
	fs.StringVar(&cpuProfile, "cpu-profile", "", "write a runtime/pprof CPU profile to this file (disabled when empty)")
	fs.StringVar(&memProfile, "mem-profile", "", "write a runtime/pprof heap profile to this file just before exit (disabled when empty)")
	fs.StringVar(&pprofHTTP, "pprof-http", "", "start a net/http/pprof server on this address (e.g. ':6060') for live profiling; disabled when empty")
	fs.IntVar(&maxPerCrossFileSink, "max-per-cross-file-sink", -1, "cap how many BATOU-INTERPROC-* findings share the same leaf sink (file+line+rule) before the rest are tagged rolled_up=true (recall preserved; default 10; 0 disables)")
	fs.BoolVar(&sarifFlag, "sarif", false, "emit a single SARIF 2.1.0 document (with taint-path codeFlows) instead of JSONL — upload to GitHub code-scanning or any SARIF viewer; honors --with-regex/--min-confidence; pair with --output FILE")
	fs.StringVar(&failOn, "fail-on", FailOnNone, "CI gate: exit 3 when any emitted finding matches LEVEL — none (default: always exit 0 on a completed scan), any, blocking (would block a write: risk_score >= 0.7), critical, or high (severity at-or-above High). The --with-regex/--regex-only/--min-confidence filters apply first: only emitted findings count.")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: batou scan [flags] DIR

Walk DIR and emit one JSON finding per line (JSONL) to stdout (or --output FILE).
JSONL is not a JSON array — slurp it with `+"`jq -s`"+` if you need one.

** DEFAULT BEHAVIOR (changed 2026-05-13) **
By default, only AST / taint / interprocedural-confirmed findings are emitted.
Regex-tier (Layer-1) findings — INCLUDING `+"`BATOU-SECRETS-*`"+` (hardcoded API keys,
AWS keys, etc.), weak-crypto, and misconfig rules — are HIDDEN by default
because they're the dominant false-positive source on real codebases.
Pass `+"`--with-regex`"+` to include them, or `+"`--regex-only`"+` to see only the regex
tier (e.g. for a secrets-only pass).

`+"`batou scan`"+` also writes/updates .batou/callgraph.json (the persistent call graph)
relative to the current directory. Pass --exclude .batou to keep that directory
out of a re-scan, --callgraph PATH to write the graph elsewhere, or --no-callgraph
to skip persistence entirely (useful for one-shot CI scans).

Examples:
  batou scan ./src                                           # dataflow-confirmed only
  batou scan --with-regex ./src                              # include regex-tier (incl. secrets)
  batou scan --regex-only ./src                              # secrets-and-crypto-only pass
  batou scan --min-confidence 0.7 ./src                      # only high-confidence findings
  batou scan --no-callgraph ./src                            # one-shot CI scan, no .batou/ writes
  batou scan --callgraph /tmp/cg.json ./src                  # custom callgraph location
  batou scan --sarif --output batou.sarif ./src              # SARIF 2.1.0 for GitHub code-scanning
  batou scan --fail-on blocking --no-callgraph ./src         # CI gate: exit 3 on would-block findings

Exit codes:
  0  scan completed; no --fail-on policy match (the default --fail-on none always exits 0)
  1  internal error (I/O failure, scan failure)
  2  usage error (bad flags / arguments)
  3  one or more emitted findings matched --fail-on (CI gate tripped)

With --sarif, output is a single SARIF 2.1.0 document (not JSONL): one result per
finding, with the source->sink taint path rendered as a SARIF codeFlow and
confidence/tier/CWE in result properties. Upload it to GitHub code-scanning with
github/codeql-action/upload-sarif, or open it in any SARIF viewer.

Output fields (per JSONL line):
  file, rule_id, severity, title, line, cwe, owasp, confidence,
  confidence_score, language, matched_text, taint_path,
  is_test_file              (bool) — path looks like a test/fixture/mock
  is_infra_file             (bool) — DB migration, build tooling, or code generator
  is_docs_file              (bool) — path is documentation (.md/.rst/.adoc, /docs/, /site/)
  is_generated_or_vendor    (bool) — vendored / minified / generated / lockfile
  source_type               (taint only) — taint source category (e.g. user_input)
  sink_type                 (taint only) — taint sink category (e.g. sql_query)

Quick triage filter — high-confidence findings in non-test, non-infra, non-vendor code:
  jq -c 'select(.confidence_score >= 0.7 and .is_test_file != true and .is_infra_file != true and .is_generated_or_vendor != true)'

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	// Mutual-exclusion: of {--with-regex, --no-regex, --regex-only}, --with-regex
	// disagrees with both other flags (one says include, the others say drop or
	// keep-only). --no-regex and --regex-only also contradict each other (drop
	// vs. keep-only). Enumerate all three pairs explicitly so the error message
	// names the offending pair.
	if withRegex && regexOnly {
		fmt.Fprintln(os.Stderr, "scan: --with-regex and --regex-only are mutually exclusive")
		return 2
	}
	if withRegex && noRegex {
		fmt.Fprintln(os.Stderr, "scan: --with-regex and --no-regex are mutually exclusive")
		return 2
	}
	if noRegex && regexOnly {
		fmt.Fprintln(os.Stderr, "scan: --no-regex and --regex-only are mutually exclusive")
		return 2
	}
	// --callgraph and --no-callgraph contradict: one redirects persistence,
	// the other disables it. Reject both together so the user gets a clear
	// error instead of a silent precedence rule.
	if callgraphPath != "" && noCallgraph {
		fmt.Fprintln(os.Stderr, "scan: --callgraph and --no-callgraph are mutually exclusive")
		return 2
	}
	// Validate --fail-on before any scanning so a typo'd policy is a usage
	// error (exit 2), not a scan that silently never gates.
	failOnPolicy, err := normalizeFailOn(failOn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: %v\n", err)
		return 2
	}
	out := io.Writer(os.Stdout)
	if outputFlag != "" {
		f, err := os.Create(outputFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan: cannot open --output file: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()
		out = f
	}
	opts := Options{
		Root:    fs.Arg(0),
		Workers: workers,
		Out:     out,
		ErrOut:  os.Stderr,
		// IncludeRegex defaults to false. --with-regex flips it on; --no-regex
		// is the compat alias for the new default (no-op in the common case).
		IncludeRegex:        withRegex,
		RegexOnly:           regexOnly,
		MinConfidence:       minConfidence,
		CallgraphPath:       callgraphPath,
		NoCallgraph:         noCallgraph,
		CPUProfile:          cpuProfile,
		MemProfile:          memProfile,
		PprofHTTP:           pprofHTTP,
		MaxPerCrossFileSink: maxPerCrossFileSink,
		SARIF:               sarifFlag,
		FailOn:              failOnPolicy,
	}
	if timeoutMs > 0 {
		opts.FileDeadline = time.Duration(timeoutMs) * time.Millisecond
	}
	if extsFlag == "*" {
		opts.Exts = nil // scan everything
	} else if extsFlag != "" {
		for _, e := range strings.Split(extsFlag, ",") {
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			opts.Exts = append(opts.Exts, e)
		}
	} else {
		opts.Exts = defaultExts
	}
	opts.Exclude = append(opts.Exclude, defaultExcludes...)
	if excludeFlag != "" {
		for _, d := range strings.Split(excludeFlag, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				opts.Exclude = append(opts.Exclude, d)
			}
		}
	}
	if quiet {
		opts.ErrOut = io.Discard
	}
	stats, err := RunStats(context.Background(), opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: %v\n", err)
		return 1
	}
	// CI gate: a completed scan whose emitted findings matched the --fail-on
	// policy exits 3 — distinct from 1 (internal error) and 2 (usage error)
	// so pipelines can tell "vulnerable" apart from "broken".
	if stats.FailOnMatches > 0 {
		fmt.Fprintf(os.Stderr, "scan: %d finding(s) matched --fail-on %s\n", stats.FailOnMatches, failOnPolicy)
		return 3
	}
	return 0
}

// Run walks opts.Root and emits JSONL findings to opts.Out. Each finding is
// embellished with the source file path so the caller can pipe without
// needing a separate per-file wrapper. Callers that need the --fail-on
// policy verdict should use RunStats instead.
func Run(ctx context.Context, opts Options) error {
	_, err := RunStats(ctx, opts)
	return err
}

// RunStats is Run plus a Stats summary: it reports how many emitted findings
// matched the Options.FailOn policy so callers (RunCLI, CI integrations) can
// turn findings into a nonzero exit code. The error return covers internal
// failures only — a scan that completed but found vulnerabilities returns
// (Stats{FailOnMatches: n>0}, nil).
func RunStats(ctx context.Context, opts Options) (Stats, error) {
	var stats Stats
	// Validate FailOn up front so library callers get an error instead of a
	// policy that silently never matches. RunCLI pre-normalizes, so this only
	// fires for direct Options misuse.
	failOnPolicy, err := normalizeFailOn(opts.FailOn)
	if err != nil {
		return stats, err
	}
	opts.FailOn = failOnPolicy
	if opts.Workers <= 0 {
		opts.Workers = runtime.GOMAXPROCS(0)
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.ErrOut == nil {
		opts.ErrOut = os.Stderr
	}
	if opts.CallgraphPath != "" && opts.NoCallgraph {
		// Defensive: RunCLI already rejects this combo, but Run is also a
		// library entry point so guard explicitly here.
		return stats, fmt.Errorf("CallgraphPath and NoCallgraph are mutually exclusive")
	}

	// Profiling setup — all three flags are no-ops when empty. The CPU profile
	// runs for the lifetime of Run; the heap profile is captured just before
	// return. The HTTP server (if enabled) keeps running until the process
	// exits, which is fine for the scan subcommand because Run returns and
	// then main exits.
	if opts.PprofHTTP != "" {
		// batou:ignore BATOU-AST-008 -- goroutine lives for the lifetime of the scan binary; opt-in via --pprof-http
		go func() {
			_, _ = fmt.Fprintf(opts.ErrOut, "pprof: serving on http://%s/debug/pprof/\n", opts.PprofHTTP)
			// batou:ignore BATOU-AST-006 -- dev-only profiling endpoint bound to user-supplied --pprof-http address; never used in prod
			// nolint:gosec // dev-only profiling server, opt-in via --pprof-http
			if err := http.ListenAndServe(opts.PprofHTTP, nil); err != nil {
				_, _ = fmt.Fprintf(opts.ErrOut, "pprof: listen %s failed: %v\n", opts.PprofHTTP, err)
			}
		}()
	}
	if opts.CPUProfile != "" {
		f, err := os.Create(opts.CPUProfile)
		if err != nil {
			return stats, fmt.Errorf("creating CPU profile: %w", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			_ = f.Close()
			return stats, fmt.Errorf("starting CPU profile: %w", err)
		}
		defer func() {
			pprof.StopCPUProfile()
			_ = f.Close()
			_, _ = fmt.Fprintf(opts.ErrOut, "pprof: wrote CPU profile %s\n", opts.CPUProfile)
		}()
	}
	if opts.MemProfile != "" {
		// Defer so the heap profile reflects steady state right before exit.
		defer func() {
			f, err := os.Create(opts.MemProfile)
			if err != nil {
				_, _ = fmt.Fprintf(opts.ErrOut, "pprof: create mem profile %s: %v\n", opts.MemProfile, err)
				return
			}
			defer func() { _ = f.Close() }()
			runtime.GC() // force a GC so the heap profile reflects live allocations
			if err := pprof.Lookup("heap").WriteTo(f, 0); err != nil {
				_, _ = fmt.Fprintf(opts.ErrOut, "pprof: write mem profile %s: %v\n", opts.MemProfile, err)
				return
			}
			_, _ = fmt.Fprintf(opts.ErrOut, "pprof: wrote mem profile %s\n", opts.MemProfile)
		}()
	}

	// Apply call-graph persistence options to the scanner package. These are
	// process-wide overrides (see scanner.CallgraphPathOverride /
	// CallgraphPersistDisabled) — set them once before the worker pool starts
	// and restore on exit so a subsequent in-process Run (or the hook path
	// later in the same binary, in tests) sees a clean default again.
	prevPath := scanner.CallgraphPathOverride
	prevDisabled := scanner.CallgraphPersistDisabled
	defer func() {
		scanner.CallgraphPathOverride = prevPath
		scanner.CallgraphPersistDisabled = prevDisabled
	}()
	scanner.CallgraphPersistDisabled = opts.NoCallgraph
	if opts.CallgraphPath != "" {
		// Resolve to an absolute path so worker goroutines (whose effective
		// cwd doesn't matter because the override is consulted directly by
		// the scanner) write to the same location the user named on the
		// command line, regardless of any later os.Chdir.
		resolved, err := filepath.Abs(opts.CallgraphPath)
		if err != nil {
			return stats, fmt.Errorf("resolving --callgraph path: %w", err)
		}
		scanner.CallgraphPathOverride = resolved
	} else {
		scanner.CallgraphPathOverride = ""
	}

	excludeSet := make(map[string]struct{}, len(opts.Exclude))
	for _, d := range opts.Exclude {
		excludeSet[d] = struct{}{}
	}
	extSet := make(map[string]struct{}, len(opts.Exts))
	for _, e := range opts.Exts {
		extSet[strings.ToLower(e)] = struct{}{}
	}
	scanAll := len(extSet) == 0

	files, err := collectFiles(opts.Root, excludeSet, extSet, scanAll)
	if err != nil {
		return stats, err
	}
	_, _ = fmt.Fprintf(opts.ErrOut, "scanning %d files with %d workers\n", len(files), opts.Workers)

	// Set up a SHARED callgraph for the worker pool. Without this,
	// every worker's scanner.Scan would load / mutate / save the
	// persistent callgraph independently, racing on the JSON file and
	// losing 15–30% of cross-file edges run-to-run. With the shared
	// pointer set, each worker mutates the same in-memory CallGraph
	// under cg.Mu, and we persist once below after the pool drains.
	if !scanner.CallgraphPersistDisabled {
		shared, _ := loadSharedCallGraph(opts.Root)
		if shared != nil {
			scanner.SharedCallGraph = shared
			// Clear after this scan returns so subsequent in-process
			// calls (tests, future Run() invocations) start clean.
			defer func() { scanner.SharedCallGraph = nil }()
		}
	}

	// Zero the cross-file cap-hit diagnostics so the summary line emitted
	// by finalizeCrossFileEdges reflects only THIS run (per-file interproc
	// in the worker pool increments them too). Output-only.
	graph.ResetCapHits()

	var (
		scanned    int64
		flows      int64
		policyHits int64 // per-file findings matching opts.FailOn
		muStat     sync.Mutex
	)

	// Each file's JSONL output is buffered into results[i] (each worker owns its
	// index, so no lock is needed) and emitted in file order after the pool
	// drains. files comes from a sorted WalkDir, so the output is deterministic
	// run to run — workers otherwise emit in nondeterministic completion order.
	results := make([][]byte, len(files))
	// SARIF mode collects typed findings per file index (parallel to results,
	// each worker owns its index so no lock is needed) and renders one document
	// after the cross-file pass; results stays nil/unused.
	var collected [][]rules.Finding
	if opts.SARIF {
		collected = make([][]rules.Finding, len(files))
	}

	// Worker pool
	type job struct {
		idx  int
		path string
	}
	jobs := make(chan job, opts.Workers*2)
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				n, hits, out, coll := scanOne(ctx, j.path, opts.FileDeadline, &opts)
				if opts.SARIF {
					collected[j.idx] = coll
				} else {
					results[j.idx] = out
				}
				muStat.Lock()
				scanned++
				flows += int64(n)
				policyHits += int64(hits)
				cur := scanned
				muStat.Unlock()
				if cur%500 == 0 {
					elapsed := time.Since(start).Seconds()
					rate := float64(cur) / elapsed
					_, _ = fmt.Fprintf(opts.ErrOut, "  [%d/%d] %.1f files/s, %d findings so far\n", cur, len(files), rate, flows)
				}
			}
		}()
	}
	for i, f := range files {
		jobs <- job{idx: i, path: f}
	}
	close(jobs)
	wg.Wait()

	// Emit in deterministic file order (results were filled by index).
	// SARIF mode defers all output to a single document below, so skip the
	// per-file JSONL stream and route cross-file findings into a collector.
	var crossFindings []rules.Finding
	if opts.SARIF {
		opts.crossSink = &crossFindings
	} else {
		for _, out := range results {
			if len(out) > 0 {
				_, _ = opts.Out.Write(out)
			}
		}
	}

	// Cross-file resolution pass — populates CallGraph.PackageIndex,
	// rewrites cross-file edges, and records ExternCalls. Per-file
	// scans only see same-file calls; this finalize step is the first
	// point at which all nodes are known, so it's the right place to
	// resolve calls that target functions in other files. Honors
	// --no-callgraph by skipping when persistence is disabled (no graph
	// to mutate or write back).
	crossHits := finalizeCrossFileEdges(opts.Root, opts, files)

	// SARIF mode: aggregate every per-file finding (in deterministic file
	// order) plus the cross-file/cross-language findings into one ScanResult
	// and render a single SARIF 2.1.0 document. Done after finalize so the
	// cross-file codeFlows are included.
	if opts.SARIF {
		all := make([]rules.Finding, 0, int(flows))
		for _, fs := range collected {
			all = append(all, fs...)
		}
		all = append(all, crossFindings...)
		// Cross-file findings were routed into crossFindings (not emitted),
		// so finalizeCrossFileEdges returned 0 — count them here instead.
		crossHits = countFailOn(opts.FailOn, crossFindings)
		sr := &reporter.ScanResult{Findings: all}
		// Pass the scan root so artifact URIs come out root-relative against a
		// SRCROOT uriBaseId (what GitHub code-scanning upload expects) instead
		// of whatever absolute/ad-hoc path was given on the command line.
		data, err := reporter.ToSARIFJSONWithRoot(sr, opts.Root)
		if err != nil {
			_, _ = fmt.Fprintf(opts.ErrOut, "scan: SARIF render failed: %v\n", err)
			return stats, err
		}
		_, _ = opts.Out.Write(data)
		_, _ = opts.Out.Write([]byte("\n"))
	}

	stats.FailOnMatches = policyHits + int64(crossHits)
	_, _ = fmt.Fprintf(opts.ErrOut, "done: %d files in %.1fs, %d findings\n", scanned, time.Since(start).Seconds(), flows)
	return stats, nil
}

// loadSharedCallGraph loads the persistent callgraph once for the
// dirscan worker pool. Returns nil when callgraph persistence is
// disabled (caller should fall back to the per-scanner load path).
func loadSharedCallGraph(scanDir string) (*graph.CallGraph, error) {
	projectRoot, _ := os.Getwd()
	if scanner.CallgraphPathOverride != "" {
		return graph.LoadGraphAt(scanner.CallgraphPathOverride, projectRoot, "")
	}
	return graph.LoadGraph(projectRoot, "")
}

// finalizeCrossFileEdges runs the cross-file resolution pass after all
// per-file scans have completed. It uses the SharedCallGraph that the
// dirscan worker pool has been mutating (avoiding a re-load), invokes
// graph.ResolveCrossFileEdges + signature propagation + the cross-
// file taint walk, and persists the final state to disk.
//
// scanDir is the directory the user passed to scan (e.g. "./gitea") —
// the per-language resolvers walk from here for go.mod / package.json
// / pyproject.toml.
//
// Returns the number of JSONL-emitted cross-file/cross-language findings
// matching opts.FailOn (always 0 in SARIF mode, where the findings are
// routed into opts.crossSink and counted by the caller instead).
func finalizeCrossFileEdges(scanDir string, opts Options, scannedFiles []string) int {
	if scanner.CallgraphPersistDisabled {
		return 0
	}
	cg := scanner.SharedCallGraph
	if cg == nil {
		// Fallback: SharedCallGraph wasn't initialised (e.g. unit
		// test) so do the legacy load-from-disk path.
		var err error
		projectRoot, _ := os.Getwd()
		if scanner.CallgraphPathOverride != "" {
			cg, err = graph.LoadGraphAt(scanner.CallgraphPathOverride, projectRoot, "")
		} else {
			cg, err = graph.LoadGraph(projectRoot, "")
		}
		if err != nil || cg == nil {
			return 0
		}
	}
	_ = cg // keep the variable declaration shape stable for the block below

	// Suppress unused-variable warnings for fields the old branch used.
	var err error
	_ = err
	stats := graph.ResolveCrossFileEdges(cg, scanDir, nil)
	_, _ = fmt.Fprintf(opts.ErrOut,
		"  cross-file: %d files scoped, %d nodes resolved (%d in-project, %d extern, %d unresolved)\n",
		stats.FilesScoped, stats.NodesResolved, stats.CrossFileEdges, stats.ExternEdges, stats.Unresolved,
	)

	// Propagate downstream sinks UP the callgraph. After this pass,
	// delegating functions inherit the sinks of the functions they
	// call (positionally, based on parameter pass-through). Multi-hop
	// chains converge in a few iterations.
	propStats := graph.PropagateSignaturesAcrossCallgraph(cg, nil)
	_, _ = fmt.Fprintf(opts.ErrOut,
		"  sig-propagation: %d iterations, %d sinks lifted to %d nodes\n",
		propStats.Iterations, propStats.SinksLifted, propStats.NodesUpdated,
	)

	// Now that cross-file edges exist on the callgraph AND signatures
	// have propagated up, walk every cross-file caller→callee pair
	// against AnalyzeCallerImpact. Per-file PropagateInterproc only
	// saw same-file CalledBy edges at the time it ran; this second
	// pass surfaces flows that span files.
	var walkStats graph.CrossFileWalkStats
	crossFindings := graph.WalkCrossFileTaintFlowsWithStats(cg, nil, &walkStats)

	// Tag (don't drop) middleware-chain duplicates that funnel into the
	// same leaf sink. opts.MaxPerCrossFileSink controls the per-group
	// cap; 0 disables. -1 / unset means "use the default".
	rolledCount := 0
	rolloverCap := opts.MaxPerCrossFileSink
	if rolloverCap < 0 {
		rolloverCap = scanner.DefaultCrossFileSinkCap
	}
	if rolloverCap > 0 && len(crossFindings) > 0 {
		crossFindings, rolledCount = scanner.MarkCrossFileSinkRollups(crossFindings, rolloverCap)
	}

	_, _ = fmt.Fprintf(opts.ErrOut,
		"  cross-file interproc: %d findings (pairs=%d callee-sink=%d callee-tainted-ret=%d content-load-fail=%d rolled-up=%d)\n",
		len(crossFindings), walkStats.Pairs, walkStats.CalleeHasSink, walkStats.CalleeTaintedRet, walkStats.ContentLoadFailed, rolledCount,
	)
	failOnHits := 0
	if len(crossFindings) > 0 {
		failOnHits += emitCrossFileFindings(crossFindings, opts)
	}

	// Tier-1: cross-file STORED-STATE taint. The call-edge walk above only
	// threads param/return across a call site; this pass connects a method
	// that writes external taint into an instance field (`self.q = source`)
	// to a method in a DIFFERENT file that reads the same field into a sink,
	// joining them by enclosing class identity. Runs after the call-edge walk
	// so it is purely additive (a separate finding class).
	storedStateFindings := graph.WalkCrossFileStoredState(cg)
	_, _ = fmt.Fprintf(opts.ErrOut,
		"  cross-file stored-state: %d findings\n",
		len(storedStateFindings),
	)
	if len(storedStateFindings) > 0 {
		failOnHits += emitCrossFileFindings(storedStateFindings, opts)
	}

	// Tier-1: cross-file MODULE-GLOBAL stored-state taint (Python). A config
	// module that holds only top-level globals (`X = os.environ[...]`) has no
	// FuncNode, so it is invisible to the cg-driven stored-state walk above.
	// This pass takes the on-disk file list (the only place the function-less
	// producer module is visible), enumerates module-level external-source
	// globals, and joins them to a sink-bearing reader in a DIFFERENT file that
	// imports the global — import-anchored so unrelated same-named globals
	// never collide.
	globalFindings := graph.WalkCrossFilePythonGlobals(cg, scannedFiles)
	_, _ = fmt.Fprintf(opts.ErrOut,
		"  cross-file module-globals: %d findings\n",
		len(globalFindings),
	)
	if len(globalFindings) > 0 {
		failOnHits += emitCrossFileFindings(globalFindings, opts)
	}

	// Cross-language HTTP service-boundary taint. Link outbound
	// request sites to the in-repo route handler serving the same path
	// regardless of language, and emit the synthesised cross-language
	// findings. Runs after sink propagation so handler sinks are populated.
	crossLangFindings := graph.CrossLangServiceBoundaryFindings(cg)
	_, _ = fmt.Fprintf(opts.ErrOut,
		"  cross-language service-boundary: %d findings\n",
		len(crossLangFindings),
	)
	if len(crossLangFindings) > 0 {
		failOnHits += emitCrossFileFindings(crossLangFindings, opts)
	}

	// Cap-truncation diagnostics: every cross-file bound (iteration
	// ceilings, depth/fan-out caps, lookback windows, file-size and
	// staleness gates) counts its hits; surface them so "no finding" is
	// distinguishable from "hit a cap". Quiet scans (no cap hit) emit
	// nothing.
	if caps := graph.SnapshotCapHits(); caps.Any() {
		_, _ = fmt.Fprintf(opts.ErrOut, "  cross-file caps hit: %s\n", caps)
	}

	if scanner.CallgraphPathOverride != "" {
		_ = graph.SaveGraphAt(cg, scanner.CallgraphPathOverride)
	} else {
		_ = graph.SaveGraph(cg)
	}
	return failOnHits
}

// emitCrossFileFindings JSONL-encodes the second-pass interproc findings
// onto opts.Out, mirroring the dirscan per-file output shape so a
// downstream consumer can ingest them with the same parser. Findings
// emitted here have multi-file taint_paths; the file/line fields point
// to the caller (where the source originated).
//
// Test / infra / docs / vendor path heuristics are applied per-finding
// so test-file findings are capped at LOW just like per-file output —
// the cross-file walker emits at full severity by default and this
// shim normalises that before serialisation.
//
// Returns the number of JSONL-emitted findings matching opts.FailOn —
// evaluated AFTER the severity/confidence caps and the MinConfidence
// filter, so the count matches exactly what the consumer sees. Findings
// routed into opts.crossSink (SARIF mode) are not counted here.
func emitCrossFileFindings(findings []rules.Finding, opts Options) int {
	failOnHits := 0
	enc := json.NewEncoder(opts.Out)
	for _, f := range findings {
		isTest := isTestFile(f.FilePath)
		isInfra := !isTest && isInfraFile(f.FilePath)
		isDocs := isDocsFile(f.FilePath)
		isGen := isGeneratedOrVendor(f.FilePath)

		// Apply the test/infra-file cap the per-file pipeline already
		// applies in scanner.go: downgrade severity to Low and cap
		// ConfidenceScore at 0.3 so test-shaped findings don't block
		// or dominate the JSONL stream. Confidence-cap lives in
		// scanner.CapInterprocConfidenceForTestPaths so per-file
		// interproc findings and cross-file ones share one rule.
		if isTest || isInfra {
			if f.Severity > rules.Low {
				f.Severity = rules.Low
				f.SeverityLabel = rules.Low.String()
			}
		}
		scanner.CapInterprocConfidenceForTestPaths(&f)

		if opts.MinConfidence > 0 && f.ConfidenceScore < opts.MinConfidence {
			continue
		}
		// SARIF mode: collect the normalized finding instead of JSONL-encoding
		// it. f already carries FilePath + TaintPath, so the SARIF location and
		// codeFlow render directly.
		if opts.crossSink != nil {
			*opts.crossSink = append(*opts.crossSink, f)
			continue
		}
		if failOnMatch(opts.FailOn, &f) {
			failOnHits++
		}
		rec := map[string]interface{}{
			"file":                   f.FilePath,
			"rule_id":                f.RuleID,
			"severity":               f.SeverityLabel,
			"title":                  f.Title,
			"line":                   f.LineNumber,
			"cwe":                    f.CWEID,
			"owasp":                  f.OWASPCategory,
			"confidence":             f.Confidence,
			"confidence_score":       f.ConfidenceScore,
			"language":               string(f.Language),
			"matched_text":           f.MatchedText,
			"taint_path":             f.TaintPath,
			"is_test_file":           isTest,
			"is_infra_file":          isInfra,
			"is_docs_file":           isDocs,
			"is_generated_or_vendor": isGen,
			"is_cross_file":          true,
		}
		if f.SourceCategory != "" {
			rec["source_type"] = f.SourceCategory
		}
		if f.SinkCategory != "" {
			rec["sink_type"] = f.SinkCategory
		}
		if f.Advisory != "" {
			rec["advisory"] = f.Advisory
		}
		if f.AdvisoryID != "" {
			rec["advisory_id"] = f.AdvisoryID
		}
		if f.RolledUp {
			rec["rolled_up"] = true
		}
		_ = enc.Encode(rec)
	}
	return failOnHits
}

// scanOne reads the file and runs one scanner.Scan, then emits each Finding
// (and each SuppressedFinding) as a JSON line. Returns the total count emitted.
// The inner scanner call doesn't take a context.Context (it has its own 10s
// per-rule timer), so we run it in a goroutine and gate the wait on ctx +
// deadline. If ctx is cancelled or deadline fires, the scanner goroutine may
// outlive us and finish into a buffered channel — harmless.
//
// opts.IncludeRegex / opts.RegexOnly / opts.MinConfidence filter r.Findings
// after the scan returns. SuppressedFindings (batou:ignore'd) are orthogonal
// to tier and are emitted unfiltered with their suppressed marker.
//
// The second return value is the number of post-filter findings matching
// opts.FailOn (0 when the policy is none/"").
func scanOne(ctx context.Context, path string, deadline time.Duration, opts *Options) (int, int, []byte, []rules.Finding) {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, nil, nil
	}
	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolInput: hook.ToolInput{
			FilePath: path,
			Content:  string(content),
		},
	}

	type result struct {
		findings   int
		failOnHits int // post-filter findings matching opts.FailOn
		suppressed int
		out        []byte
		coll       []rules.Finding
	}
	resCh := make(chan result, 1)
	go func(ctx context.Context) {
		r := scanner.Scan(input)
		// Drop the result if the caller has already moved on.
		if ctx.Err() != nil {
			resCh <- result{}
			return
		}
		findings := filterFindings(r.Findings, opts)
		// SARIF mode collects the typed findings instead of JSONL-encoding them;
		// the caller aggregates per-file slices in file order and renders one
		// SARIF document after the cross-file pass. Stamp FilePath so the SARIF
		// primary-location URI is populated (the JSONL path uses the loop var).
		if opts.SARIF {
			coll := make([]rules.Finding, len(findings))
			copy(coll, findings)
			for i := range coll {
				if coll[i].FilePath == "" {
					coll[i].FilePath = path
				}
			}
			resCh <- result{findings: len(findings), failOnHits: countFailOn(opts.FailOn, findings), suppressed: len(r.SuppressedFindings), coll: coll}
			return
		}
		// Compute path-based triage flags once per file — they don't depend
		// on the individual finding, only on the path.
		isTest := isTestFile(path)
		isInfra := !isTest && isInfraFile(path)
		isDocs := isDocsFile(path)
		isGenVendor := isGeneratedOrVendor(path)
		// Encode this file's findings into a private buffer; the caller emits
		// buffers in file order so the output is deterministic.
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, f := range findings {
			rec := map[string]interface{}{
				"file":             path,
				"rule_id":          f.RuleID,
				"severity":         f.SeverityLabel,
				"title":            f.Title,
				"line":             f.LineNumber,
				"cwe":              f.CWEID,
				"owasp":            f.OWASPCategory,
				"confidence":       f.Confidence,
				"confidence_score": f.ConfidenceScore,
				"language":         string(f.Language),
				"matched_text":     f.MatchedText,
				"taint_path":       f.TaintPath,
				// Triage flags — cheap, path-derived. Always present so a
				// triager can `jq 'select(.is_test_file != true)'` without
				// worrying about key absence.
				"is_test_file":           isTest,
				"is_infra_file":          isInfra,
				"is_docs_file":           isDocs,
				"is_generated_or_vendor": isGenVendor,
			}
			// source_type / sink_type are taint-only; omit them entirely for
			// non-taint findings so `jq 'select(.sink_type=="sql_query")'`
			// stays clean (no need to handle empty-string vs missing).
			if f.SourceCategory != "" {
				rec["source_type"] = f.SourceCategory
			}
			if f.SinkCategory != "" {
				rec["sink_type"] = f.SinkCategory
			}
			// advisory / advisory_id are DEPVULN-only (untrusted data reaching a
			// known-vulnerable library function); omit them entirely otherwise.
			if f.Advisory != "" {
				rec["advisory"] = f.Advisory
			}
			if f.AdvisoryID != "" {
				rec["advisory_id"] = f.AdvisoryID
			}
			_ = enc.Encode(rec)
		}
		resCh <- result{findings: len(findings), failOnHits: countFailOn(opts.FailOn, findings), suppressed: len(r.SuppressedFindings), out: buf.Bytes()}
	}(ctx)

	var timeout <-chan time.Time
	if deadline > 0 {
		timer := time.NewTimer(deadline)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case r := <-resCh:
		return r.findings, r.failOnHits, r.out, r.coll
	case <-timeout:
		return 0, 0, nil, nil
	case <-ctx.Done():
		return 0, 0, nil, nil
	}
}

// filterFindings applies the tier / confidence filters from opts to a slice of
// findings (post-dedup). It is a no-op only when the caller explicitly asked
// for everything (IncludeRegex=true && !RegexOnly && MinConfidence<=0). With
// the default Options{} it drops regex-tier findings — that is the new default
// `batou scan` behavior as of 2026-05-13.
//
// A finding whose FindingTier == TierRegex in this (already deduplicated)
// slice is one that no higher analysis layer confirmed — exactly what
// IncludeRegex=false drops. A regex finding that taint/AST confirmed on the
// same line was already replaced by the higher-tier winner during
// DeduplicateFindings, so it survives IncludeRegex=false.
func filterFindings(findings []rules.Finding, opts *Options) []rules.Finding {
	if opts == nil {
		// nil opts behaves like the new default (drop regex-tier). Callers that
		// want the old "emit everything" behavior must pass &Options{IncludeRegex: true}.
		opts = &Options{}
	}
	// No-op fast path: caller wants everything (no tier or confidence filtering).
	if opts.IncludeRegex && !opts.RegexOnly && opts.MinConfidence <= 0 {
		return findings
	}
	out := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		tier := scanner.FindingTier(&f)
		// Default (IncludeRegex=false) drops regex-tier findings, unless
		// RegexOnly explicitly asks to keep only them.
		if !opts.IncludeRegex && !opts.RegexOnly && tier == scanner.TierRegex {
			continue
		}
		if opts.RegexOnly && tier != scanner.TierRegex {
			continue
		}
		if opts.MinConfidence > 0 && f.ConfidenceScore < opts.MinConfidence {
			continue
		}
		out = append(out, f)
	}
	return out
}

func collectFiles(root string, exclude map[string]struct{}, exts map[string]struct{}, scanAll bool) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if _, skip := exclude[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if scanAll {
			out = append(out, path)
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if _, ok := exts[ext]; ok {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}
