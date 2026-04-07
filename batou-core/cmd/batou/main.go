package main

import (
	"fmt"
	"os"

	"github.com/turenlabs/batou-core/findings"
	"github.com/turenlabs/batou-core/hook"
	"github.com/turenlabs/batou-core/ledger"
	"github.com/turenlabs/batou-core/reporter"
	"github.com/turenlabs/batou-core/scanner"

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
	ledger.Record(input.SessionID, result)

	// Persist findings to project-local .batou/findings.json
	persistFindings(result)

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
			hook.OutputPreTool("allow", "Batou: security analysis complete", context)
		}

		if result.ShouldBlock() {
			// Block critical vulnerabilities BEFORE they're written
			hook.BlockWrite(reporter.FormatBlockMessage(result))
		}
	} else {
		// PostToolUse: always provide hints
		if context != "" {
			hook.OutputPostTool(context)
		}
	}
}

// persistFindings saves scan results to the project-local findings store.
// Errors are logged but do not affect hook output — findings are best-effort.
func persistFindings(result *reporter.ScanResult) {
	batouDir, err := findings.FindRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Batou: findings store: %v\n", err)
		return
	}

	store, err := findings.Open(batouDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Batou: findings store: %v\n", err)
		return
	}

	seenKeys := make(map[string]bool)
	for _, f := range result.Findings {
		store.Upsert(f)
		seenKeys[findings.DedupKey(f)] = true
	}
	for _, f := range result.SuppressedFindings {
		store.UpsertSuppressed(f, "batou:ignore")
		seenKeys[findings.DedupKey(f)] = true
	}

	// Mark findings for this file that weren't seen in this scan as resolved
	if result.FilePath != "" {
		store.MarkResolved(result.FilePath, seenKeys)
	}

	if err := store.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Batou: findings store: %v\n", err)
	}
}
