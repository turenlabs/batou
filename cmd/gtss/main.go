package main

import (
	"fmt"
	"os"

	"github.com/turen/gtss/internal/hook"
	"github.com/turen/gtss/internal/ledger"
	"github.com/turen/gtss/internal/reporter"
	"github.com/turen/gtss/internal/scanner"

	// Import all rule packages to trigger init() registrations
	_ "github.com/turen/gtss/internal/rules/injection"
	_ "github.com/turen/gtss/internal/rules/secrets"
	_ "github.com/turen/gtss/internal/rules/crypto"
	_ "github.com/turen/gtss/internal/rules/xss"
	_ "github.com/turen/gtss/internal/rules/traversal"
	_ "github.com/turen/gtss/internal/rules/ssrf"
	_ "github.com/turen/gtss/internal/rules/auth"
	_ "github.com/turen/gtss/internal/rules/generic"
	_ "github.com/turen/gtss/internal/rules/logging"
	_ "github.com/turen/gtss/internal/rules/validation"
	_ "github.com/turen/gtss/internal/rules/memory"
	_ "github.com/turen/gtss/internal/rules/nosql"
	_ "github.com/turen/gtss/internal/rules/xxe"
	_ "github.com/turen/gtss/internal/rules/redirect"
	_ "github.com/turen/gtss/internal/rules/graphql"
	_ "github.com/turen/gtss/internal/rules/misconfig"
	_ "github.com/turen/gtss/internal/rules/deser"
	_ "github.com/turen/gtss/internal/rules/framework"
	_ "github.com/turen/gtss/internal/rules/prototype"
	_ "github.com/turen/gtss/internal/rules/massassign"
	_ "github.com/turen/gtss/internal/rules/cors"
	_ "github.com/turen/gtss/internal/rules/kotlin"
	_ "github.com/turen/gtss/internal/rules/groovy"
	_ "github.com/turen/gtss/internal/rules/perl"
	_ "github.com/turen/gtss/internal/rules/lua"
	_ "github.com/turen/gtss/internal/rules/swift"
	_ "github.com/turen/gtss/internal/rules/csharp"
	_ "github.com/turen/gtss/internal/rules/rust"
	_ "github.com/turen/gtss/internal/rules/php"
	_ "github.com/turen/gtss/internal/rules/ruby"
	_ "github.com/turen/gtss/internal/rules/python"
	_ "github.com/turen/gtss/internal/rules/java"
	_ "github.com/turen/gtss/internal/rules/jsts"
	_ "github.com/turen/gtss/internal/rules/golang"
	_ "github.com/turen/gtss/internal/analyzer/goast"
	_ "github.com/turen/gtss/internal/analyzer/pyast"
	_ "github.com/turen/gtss/internal/analyzer/javaast"
	_ "github.com/turen/gtss/internal/analyzer/jsast"
	_ "github.com/turen/gtss/internal/analyzer/cast"
	_ "github.com/turen/gtss/internal/analyzer/phpast"
	_ "github.com/turen/gtss/internal/analyzer/rubyast"
	_ "github.com/turen/gtss/internal/analyzer/rustast"
	_ "github.com/turen/gtss/internal/analyzer/csast"
	_ "github.com/turen/gtss/internal/analyzer/ktast"
	_ "github.com/turen/gtss/internal/analyzer/swiftast"
	_ "github.com/turen/gtss/internal/analyzer/luaast"
	_ "github.com/turen/gtss/internal/analyzer/gvyast"

	// Taint analysis engine and language catalogs
	_ "github.com/turen/gtss/internal/taint"
	_ "github.com/turen/gtss/internal/taint/languages"
	_ "github.com/turen/gtss/internal/taint/goflow"
)

func main() {
	input, err := hook.ReadInput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "GTSS: failed to read input: %v\n", err)
		os.Exit(1)
	}

	result := scanner.Scan(input)

	// Record to ledger synchronously — it's a single JSON line append, very fast.
	// A fire-and-forget goroutine would be killed on os.Exit, losing blocked-write records.
	ledger.Record(input.SessionID, result)

	// ALWAYS output hints as additionalContext — this is the key innovation.
	// Even clean code gets a "looks good" message so Claude knows GTSS is active.
	context := result.HintsOutput

	// If no hints were generated, fall back to the traditional finding report
	if context == "" && result.HasFindings() {
		context = reporter.FormatForClaude(result)
	}

	if input.IsPreToolUse() {
		// Output context BEFORE a potential BlockWrite, since BlockWrite calls os.Exit(2).
		// This ensures Claude always receives the additionalContext hints.
		if context != "" {
			hook.OutputPreTool("allow", "GTSS: security analysis complete", context)
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
