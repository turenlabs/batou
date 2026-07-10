package main

import (
	"fmt"
	"io"
	"os"

	"github.com/turenlabs/batou-core/findings"
	"github.com/turenlabs/batou-core/hints"
	"github.com/turenlabs/batou-core/hook"
	"github.com/turenlabs/batou-core/ledger"
	"github.com/turenlabs/batou-core/reporter"
	"github.com/turenlabs/batou-core/scanner"
	"github.com/turenlabs/batou-core/scanner/dirscan"
	"github.com/turenlabs/batou-rules/rules"

	// Import all rule packages to trigger init() registrations
	_ "github.com/turenlabs/batou-core/analyzer/cast"
	_ "github.com/turenlabs/batou-core/analyzer/csast"
	_ "github.com/turenlabs/batou-core/analyzer/goast"
	_ "github.com/turenlabs/batou-core/analyzer/gvyast"
	_ "github.com/turenlabs/batou-core/analyzer/javaast"
	_ "github.com/turenlabs/batou-core/analyzer/jsast"
	_ "github.com/turenlabs/batou-core/analyzer/ktast"
	_ "github.com/turenlabs/batou-core/analyzer/luaast"
	_ "github.com/turenlabs/batou-core/analyzer/perlast"
	_ "github.com/turenlabs/batou-core/analyzer/phpast"
	_ "github.com/turenlabs/batou-core/analyzer/pyast"
	_ "github.com/turenlabs/batou-core/analyzer/rubyast"
	_ "github.com/turenlabs/batou-core/analyzer/rustast"
	_ "github.com/turenlabs/batou-core/analyzer/shellast"
	_ "github.com/turenlabs/batou-core/analyzer/swiftast"
	_ "github.com/turenlabs/batou-core/analyzer/zigast"
	_ "github.com/turenlabs/batou-rules/rules/auth"
	_ "github.com/turenlabs/batou-rules/rules/container"
	_ "github.com/turenlabs/batou-rules/rules/cors"
	_ "github.com/turenlabs/batou-rules/rules/crypto"
	_ "github.com/turenlabs/batou-rules/rules/csharp"
	_ "github.com/turenlabs/batou-rules/rules/deser"
	_ "github.com/turenlabs/batou-rules/rules/encoding"
	_ "github.com/turenlabs/batou-rules/rules/framework"
	_ "github.com/turenlabs/batou-rules/rules/generic"
	_ "github.com/turenlabs/batou-rules/rules/golang"
	_ "github.com/turenlabs/batou-rules/rules/graphql"
	_ "github.com/turenlabs/batou-rules/rules/groovy"
	_ "github.com/turenlabs/batou-rules/rules/header"
	_ "github.com/turenlabs/batou-rules/rules/injection"
	_ "github.com/turenlabs/batou-rules/rules/java"
	_ "github.com/turenlabs/batou-rules/rules/jsts"
	_ "github.com/turenlabs/batou-rules/rules/jwt"
	_ "github.com/turenlabs/batou-rules/rules/kotlin"
	_ "github.com/turenlabs/batou-rules/rules/logging"
	_ "github.com/turenlabs/batou-rules/rules/lua"
	_ "github.com/turenlabs/batou-rules/rules/massassign"
	_ "github.com/turenlabs/batou-rules/rules/memory"
	_ "github.com/turenlabs/batou-rules/rules/misconfig"
	_ "github.com/turenlabs/batou-rules/rules/nosql"
	_ "github.com/turenlabs/batou-rules/rules/oauth"
	_ "github.com/turenlabs/batou-rules/rules/perl"
	_ "github.com/turenlabs/batou-rules/rules/php"
	_ "github.com/turenlabs/batou-rules/rules/prototype"
	_ "github.com/turenlabs/batou-rules/rules/python"
	_ "github.com/turenlabs/batou-rules/rules/race"
	_ "github.com/turenlabs/batou-rules/rules/redirect"
	_ "github.com/turenlabs/batou-rules/rules/ruby"
	_ "github.com/turenlabs/batou-rules/rules/rust"
	_ "github.com/turenlabs/batou-rules/rules/secrets"
	_ "github.com/turenlabs/batou-rules/rules/session"
	_ "github.com/turenlabs/batou-rules/rules/ssrf"
	_ "github.com/turenlabs/batou-rules/rules/ssti"
	_ "github.com/turenlabs/batou-rules/rules/swift"
	_ "github.com/turenlabs/batou-rules/rules/traversal"
	_ "github.com/turenlabs/batou-rules/rules/upload"
	_ "github.com/turenlabs/batou-rules/rules/validation"
	_ "github.com/turenlabs/batou-rules/rules/websocket"
	_ "github.com/turenlabs/batou-rules/rules/xss"
	_ "github.com/turenlabs/batou-rules/rules/xxe"
	_ "github.com/turenlabs/batou-rules/rules/zig"

	// Taint analysis engine and language catalogs
	_ "github.com/turenlabs/batou-core/taint/languages"
	_ "github.com/turenlabs/batou-core/taintrule"
)

// version is overridable at link time via -ldflags "-X 'main.version=...'".
var version = "dev"

func main() {
	// Explicit help/version flags — handled before anything reads stdin so
	// `batou help` works whether or not a pipe is attached. These only fire
	// when the first arg is one of the recognized verbs/flags, so a real hook
	// invocation (len(os.Args)==1) never hits this path.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "help", "--help", "-h":
			printUsage(os.Stdout)
			os.Exit(0)
		case "version", "--version", "-v":
			fmt.Println(version)
			os.Exit(0)
		}
	}

	// Subcommand routing: `batou findings [flags]` and `batou scan DIR`.
	if len(os.Args) > 1 && os.Args[1] == "findings" {
		os.Exit(findings.RunCLI(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "scan" {
		os.Exit(dirscan.RunCLI(os.Args[2:]))
	}

	// Bare `batou` from an interactive terminal is almost certainly a human
	// who expected `--help`, not a Claude Code hook (which always pipes JSON
	// on stdin). Print usage and exit cleanly instead of blocking on a read
	// that will never complete. This only triggers when stdin is a character
	// device — a real hook run pipes stdin, so ModeCharDevice is unset and we
	// fall through to the normal hook path below, byte-for-byte unchanged.
	if len(os.Args) == 1 && wantInteractiveUsage(os.Args[1:], stdinIsCharDevice()) {
		printUsage(os.Stderr)
		os.Exit(0)
	}

	input, err := hook.ReadInput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Batou: failed to read input: %v\n", err)
		os.Exit(1)
	}

	// Guard against accidental misuse: someone piping arbitrary JSON (e.g.
	// `echo '{"repo_path":"..."}' | batou`) instead of a Claude Code hook
	// event. ReadInput() succeeds on any well-formed JSON, producing an Input
	// with empty fields, which would otherwise scan nothing and silently write
	// an empty .batou/findings.json. A genuine hook event always carries at
	// least a hook_event_name or a touched file path/content, so this guard
	// can never fire on the real hook path.
	if input.HookEventName == "" && input.ResolvePath() == "" && input.ResolveContent() == "" {
		fmt.Fprintln(os.Stderr, "Batou: stdin doesn't look like a Claude Code hook event (no hook_event_name / file content).")
		fmt.Fprintln(os.Stderr, "If you want to scan a directory, use:  batou scan <dir>")
		fmt.Fprintln(os.Stderr, "Run  batou help  for usage.")
		os.Exit(0)
	}

	result := scanner.Scan(input)

	// Record to ledger synchronously — it's a single JSON line append, very fast.
	// A fire-and-forget goroutine would be killed on os.Exit, losing blocked-write records.
	_ = ledger.Record(input.SessionID, result)

	// Persist findings and compute lifecycle deltas for hint enrichment.
	// Deltas track new/recurring/fixed findings so Claude gets feedback.
	deltas := persistFindings(result)

	// Tag each finding with lifecycle status so downstream consumers
	// (external dashboards, metrics sinks) can track new/recurring/fixed.
	if deltas != nil {
		tagFindingsLifecycle(result.Findings, deltas)
	}

	// Inject lifecycle tags into the hints output if deltas are available.
	if deltas != nil && result.HintsOutput != "" {
		result.HintsOutput = hints.InjectLifecycle(result.HintsOutput, deltas, result.Findings)
	}

	// ALWAYS output hints as additionalContext — this is the key innovation.
	// Even clean code gets a "looks good" message so Claude knows Batou is active.
	context := result.HintsOutput

	// If no hints were generated, fall back to the traditional finding report
	if context == "" && result.HasFindings() {
		context = reporter.FormatForClaude(result)
	}

	if input.IsPreToolUse() {
		// Output context BEFORE a potential BlockWrite, since BlockWrite calls os.Exit(2).
		// This ensures Claude always receives the additionalContext hints.
		if context != "" {
			_ = hook.OutputPreTool("allow", "Batou: security analysis complete", context)
		}

		shouldBlock := result.ShouldBlock() || result.PreSuppressBlock
		if shouldBlock && !result.SuppressOnlyEdit {
			// Block critical vulnerabilities BEFORE they're written.
			// PreSuppressBlock catches the bypass where an agent adds
			// batou:ignore directives to hide blocking findings — the
			// findings were blocking before suppression was applied.
			// Exception: suppress-only edits (adding batou:ignore directives)
			// are allowed through to break the chicken-and-egg deadlock.
			hook.BlockWrite(reporter.FormatBlockMessage(result))
		}
	} else {
		// PostToolUse: always provide hints
		if context != "" {
			_ = hook.OutputPostTool(context)
		}
	}
}

// printUsage writes the top-level usage text to w.
func printUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `batou — code guard / SAST scanner

Usage:
  batou                  (hook mode) read a Claude Code hook event on stdin, scan the touched
                         file, and emit security hints. Invoked automatically by the Claude Code
                         PreToolUse/PostToolUse hooks — not meant to be run by hand.
  batou scan <dir>       scan a directory tree; emit one JSON finding per line (JSONL) to stdout
  batou findings         report the project-local findings cache (.batou/findings.json)
  batou version          print version
  batou help             show this message

Examples:
  batou scan ./src > findings.jsonl
  batou scan --exclude .batou,node_modules /path/to/repo | jq -s 'length'
  batou scan --quiet . | jq -c 'select(.taint_path != null) | {file:.file, line:.line, rule:.rule_id}'
  batou scan --fail-on blocking --no-callgraph ./src   # CI gate: exit 3 when a blocking finding is emitted

`+"`batou scan`"+` also writes/updates .batou/callgraph.json (the persistent call graph) relative
to the cwd; the JSONL on stdout is the authoritative per-run output. Pass --exclude .batou to
keep that directory out of a re-scan, --callgraph PATH to redirect the graph, or --no-callgraph
to skip persistence entirely. See `+"`batou scan --help`"+` for flags.
`)
}

// stdinIsCharDevice reports whether os.Stdin is an interactive terminal (a
// character device) rather than a pipe or file. A real Claude Code hook
// invocation pipes JSON on stdin, so this returns false in that case.
func stdinIsCharDevice() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

// wantInteractiveUsage decides whether a bare `batou` invocation should print
// usage instead of waiting for hook input on stdin. It returns true only when
// there are no args at all and stdin is an interactive terminal. Help/version
// and the subcommands are dispatched earlier, so a non-empty args slice always
// returns false here.
func wantInteractiveUsage(args []string, stdinIsCharDevice bool) bool {
	return len(args) == 0 && stdinIsCharDevice
}

// persistFindings saves scan results to the project-local findings store
// and returns lifecycle deltas (new/recurring/fixed) for hint enrichment.
// Errors are logged but do not affect hook output — findings are best-effort.
func persistFindings(result *reporter.ScanResult) *findings.Deltas {
	batouDir, err := findings.FindRoot(result.FilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Batou: findings store: %v\n", err)
		return nil
	}

	store, err := findings.Open(batouDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Batou: findings store: %v\n", err)
		return nil
	}

	// ComputeDeltas upserts findings and marks resolved in one pass.
	// Pass suppressed findings so they aren't incorrectly marked as resolved.
	var deltas *findings.Deltas
	if result.FilePath != "" {
		deltas = store.ComputeDeltas(result.FilePath, result.Findings, result.SuppressedFindings)
	}

	// Record suppressed findings with their suppress status. The scanner
	// stamps each suppressed finding with the directive's `-- reason` text
	// (Finding.SuppressReason); persist it so the audit trail keeps the
	// developer's justification, not just the fact a directive existed.
	for _, f := range result.SuppressedFindings {
		reason := "batou:ignore"
		if f.SuppressReason != "" {
			reason = "batou:ignore -- " + f.SuppressReason
		}
		store.UpsertSuppressed(f, reason)
	}

	if err := store.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Batou: findings store: %v\n", err)
	}

	return deltas
}

// tagFindingsLifecycle annotates each finding with lifecycle metadata derived
// from the findings store deltas. This ensures the fields are populated before
// IPC serialization to external dashboards and metrics sinks.
func tagFindingsLifecycle(allFindings []rules.Finding, deltas *findings.Deltas) {
	newKeys := make(map[string]bool, len(deltas.New))
	for _, f := range deltas.New {
		newKeys[findings.DedupKey(f)] = true
	}

	for i := range allFindings {
		key := findings.DedupKey(allFindings[i])
		allFindings[i].DedupKey = key

		if newKeys[key] {
			allFindings[i].LifecycleStatus = "new"
			allFindings[i].SeenCount = 1
		} else {
			allFindings[i].LifecycleStatus = "recurring"
			allFindings[i].SeenCount = deltas.RecurringCount(allFindings[i])
		}
	}
}
