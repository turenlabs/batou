package main

import (
	"fmt"
	"os"

	"github.com/turenlabs/batou/internal/findings"
	"github.com/turenlabs/batou/internal/hook"
	"github.com/turenlabs/batou/internal/ledger"
	"github.com/turenlabs/batou/internal/reporter"
	"github.com/turenlabs/batou/internal/scanner"

	// Import all rule packages to trigger init() registrations
	_ "github.com/turenlabs/batou/internal/rules/injection"
	_ "github.com/turenlabs/batou/internal/rules/secrets"
	_ "github.com/turenlabs/batou/internal/rules/crypto"
	_ "github.com/turenlabs/batou/internal/rules/xss"
	_ "github.com/turenlabs/batou/internal/rules/traversal"
	_ "github.com/turenlabs/batou/internal/rules/ssrf"
	_ "github.com/turenlabs/batou/internal/rules/auth"
	_ "github.com/turenlabs/batou/internal/rules/generic"
	_ "github.com/turenlabs/batou/internal/rules/logging"
	_ "github.com/turenlabs/batou/internal/rules/validation"
	_ "github.com/turenlabs/batou/internal/rules/memory"
	_ "github.com/turenlabs/batou/internal/rules/nosql"
	_ "github.com/turenlabs/batou/internal/rules/xxe"
	_ "github.com/turenlabs/batou/internal/rules/redirect"
	_ "github.com/turenlabs/batou/internal/rules/graphql"
	_ "github.com/turenlabs/batou/internal/rules/misconfig"
	_ "github.com/turenlabs/batou/internal/rules/deser"
	_ "github.com/turenlabs/batou/internal/rules/framework"
	_ "github.com/turenlabs/batou/internal/rules/prototype"
	_ "github.com/turenlabs/batou/internal/rules/massassign"
	_ "github.com/turenlabs/batou/internal/rules/cors"
	_ "github.com/turenlabs/batou/internal/rules/header"
	_ "github.com/turenlabs/batou/internal/rules/encoding"
	_ "github.com/turenlabs/batou/internal/rules/container"
	_ "github.com/turenlabs/batou/internal/rules/ssti"
	_ "github.com/turenlabs/batou/internal/rules/jwt"
	_ "github.com/turenlabs/batou/internal/rules/session"
	_ "github.com/turenlabs/batou/internal/rules/upload"
	_ "github.com/turenlabs/batou/internal/rules/race"
	_ "github.com/turenlabs/batou/internal/rules/websocket"
	_ "github.com/turenlabs/batou/internal/rules/oauth"
	_ "github.com/turenlabs/batou/internal/rules/kotlin"
	_ "github.com/turenlabs/batou/internal/rules/groovy"
	_ "github.com/turenlabs/batou/internal/rules/perl"
	_ "github.com/turenlabs/batou/internal/rules/lua"
	_ "github.com/turenlabs/batou/internal/rules/swift"
	_ "github.com/turenlabs/batou/internal/rules/csharp"
	_ "github.com/turenlabs/batou/internal/rules/rust"
	_ "github.com/turenlabs/batou/internal/rules/php"
	_ "github.com/turenlabs/batou/internal/rules/ruby"
	_ "github.com/turenlabs/batou/internal/rules/python"
	_ "github.com/turenlabs/batou/internal/rules/java"
	_ "github.com/turenlabs/batou/internal/rules/jsts"
	_ "github.com/turenlabs/batou/internal/rules/golang"
	_ "github.com/turenlabs/batou/internal/analyzer/goast"
	_ "github.com/turenlabs/batou/internal/analyzer/pyast"
	_ "github.com/turenlabs/batou/internal/analyzer/javaast"
	_ "github.com/turenlabs/batou/internal/analyzer/jsast"
	_ "github.com/turenlabs/batou/internal/analyzer/cast"
	_ "github.com/turenlabs/batou/internal/analyzer/phpast"
	_ "github.com/turenlabs/batou/internal/analyzer/rubyast"
	_ "github.com/turenlabs/batou/internal/analyzer/rustast"
	_ "github.com/turenlabs/batou/internal/analyzer/csast"
	_ "github.com/turenlabs/batou/internal/analyzer/ktast"
	_ "github.com/turenlabs/batou/internal/analyzer/swiftast"
	_ "github.com/turenlabs/batou/internal/analyzer/luaast"
	_ "github.com/turenlabs/batou/internal/analyzer/gvyast"

	// Taint analysis engine and language catalogs
	_ "github.com/turenlabs/batou/internal/taintrule"
	_ "github.com/turenlabs/batou/internal/taint/languages"
	_ "github.com/turenlabs/batou/internal/taint/goflow"
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
