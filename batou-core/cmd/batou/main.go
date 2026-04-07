package main

import (
	"fmt"
	"os"

	"github.com/turenlabs/batou-core/findings"
	"github.com/turenlabs/batou-core/hints"
	"github.com/turenlabs/batou-core/hook"
	"github.com/turenlabs/batou-core/ledger"
	"github.com/turenlabs/batou-core/reporter"
	"github.com/turenlabs/batou-core/scanner"
	"github.com/turenlabs/batou-rules/rules"

	// Import all rule packages to trigger init() registrations
	_ "github.com/turenlabs/batou-rules/rules/injection"
	_ "github.com/turenlabs/batou-rules/rules/secrets"
	_ "github.com/turenlabs/batou-rules/rules/crypto"
	_ "github.com/turenlabs/batou-rules/rules/xss"
	_ "github.com/turenlabs/batou-rules/rules/traversal"
	_ "github.com/turenlabs/batou-rules/rules/ssrf"
	_ "github.com/turenlabs/batou-rules/rules/auth"
	_ "github.com/turenlabs/batou-rules/rules/generic"
	_ "github.com/turenlabs/batou-rules/rules/logging"
	_ "github.com/turenlabs/batou-rules/rules/validation"
	_ "github.com/turenlabs/batou-rules/rules/memory"
	_ "github.com/turenlabs/batou-rules/rules/nosql"
	_ "github.com/turenlabs/batou-rules/rules/xxe"
	_ "github.com/turenlabs/batou-rules/rules/redirect"
	_ "github.com/turenlabs/batou-rules/rules/graphql"
	_ "github.com/turenlabs/batou-rules/rules/misconfig"
	_ "github.com/turenlabs/batou-rules/rules/deser"
	_ "github.com/turenlabs/batou-rules/rules/framework"
	_ "github.com/turenlabs/batou-rules/rules/prototype"
	_ "github.com/turenlabs/batou-rules/rules/massassign"
	_ "github.com/turenlabs/batou-rules/rules/cors"
	_ "github.com/turenlabs/batou-rules/rules/header"
	_ "github.com/turenlabs/batou-rules/rules/encoding"
	_ "github.com/turenlabs/batou-rules/rules/container"
	_ "github.com/turenlabs/batou-rules/rules/ssti"
	_ "github.com/turenlabs/batou-rules/rules/jwt"
	_ "github.com/turenlabs/batou-rules/rules/session"
	_ "github.com/turenlabs/batou-rules/rules/upload"
	_ "github.com/turenlabs/batou-rules/rules/race"
	_ "github.com/turenlabs/batou-rules/rules/websocket"
	_ "github.com/turenlabs/batou-rules/rules/oauth"
	_ "github.com/turenlabs/batou-rules/rules/kotlin"
	_ "github.com/turenlabs/batou-rules/rules/groovy"
	_ "github.com/turenlabs/batou-rules/rules/perl"
	_ "github.com/turenlabs/batou-rules/rules/lua"
	_ "github.com/turenlabs/batou-rules/rules/swift"
	_ "github.com/turenlabs/batou-rules/rules/csharp"
	_ "github.com/turenlabs/batou-rules/rules/rust"
	_ "github.com/turenlabs/batou-rules/rules/zig"
	_ "github.com/turenlabs/batou-rules/rules/php"
	_ "github.com/turenlabs/batou-rules/rules/ruby"
	_ "github.com/turenlabs/batou-rules/rules/python"
	_ "github.com/turenlabs/batou-rules/rules/java"
	_ "github.com/turenlabs/batou-rules/rules/jsts"
	_ "github.com/turenlabs/batou-rules/rules/golang"
	_ "github.com/turenlabs/batou-core/analyzer/goast"
	_ "github.com/turenlabs/batou-core/analyzer/pyast"
	_ "github.com/turenlabs/batou-core/analyzer/javaast"
	_ "github.com/turenlabs/batou-core/analyzer/jsast"
	_ "github.com/turenlabs/batou-core/analyzer/cast"
	_ "github.com/turenlabs/batou-core/analyzer/phpast"
	_ "github.com/turenlabs/batou-core/analyzer/rubyast"
	_ "github.com/turenlabs/batou-core/analyzer/rustast"
	_ "github.com/turenlabs/batou-core/analyzer/csast"
	_ "github.com/turenlabs/batou-core/analyzer/ktast"
	_ "github.com/turenlabs/batou-core/analyzer/swiftast"
	_ "github.com/turenlabs/batou-core/analyzer/luaast"
	_ "github.com/turenlabs/batou-core/analyzer/gvyast"

	// Taint analysis engine and language catalogs
	_ "github.com/turenlabs/batou-core/taintrule"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

func main() {
	// Subcommand routing: `batou findings [flags]`
	if len(os.Args) > 1 && os.Args[1] == "findings" {
		os.Exit(findings.RunCLI(os.Args[2:]))
	}

	input, err := hook.ReadInput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Batou: failed to read input: %v\n", err)
		os.Exit(1)
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

	// Record suppressed findings with their suppress status.
	for _, f := range result.SuppressedFindings {
		store.UpsertSuppressed(f, "batou:ignore")
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
