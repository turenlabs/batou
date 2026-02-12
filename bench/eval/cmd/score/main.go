// Command score is the ProductSecBench CLI evaluation tool.
//
// It loads a prompt corpus and model-generated code samples, runs the GTSS
// scanner on each sample, and produces an evaluation report.
//
// Usage:
//
//	go run ./bench/eval/cmd/score \
//	  --prompts=bench/prompts/ \
//	  --results=bench/results/claude-sonnet/ \
//	  --output=bench/reports/claude-sonnet.json \
//	  --format=table \
//	  --model=claude-sonnet
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/turen/gtss/bench/eval"

	// Import rule packages to trigger init() registrations.
	_ "github.com/turen/gtss/internal/rules/auth"
	_ "github.com/turen/gtss/internal/rules/crypto"
	_ "github.com/turen/gtss/internal/rules/generic"
	_ "github.com/turen/gtss/internal/rules/injection"
	_ "github.com/turen/gtss/internal/rules/logging"
	_ "github.com/turen/gtss/internal/rules/memory"
	_ "github.com/turen/gtss/internal/rules/secrets"
	_ "github.com/turen/gtss/internal/rules/ssrf"
	_ "github.com/turen/gtss/internal/rules/traversal"
	_ "github.com/turen/gtss/internal/rules/validation"
	_ "github.com/turen/gtss/internal/rules/xss"

	// Taint analysis engine and language catalogs.
	_ "github.com/turen/gtss/internal/analyzer/goast"
	_ "github.com/turen/gtss/internal/taint"
	_ "github.com/turen/gtss/internal/taint/goflow"
	_ "github.com/turen/gtss/internal/taint/languages"
)

func main() {
	promptsDir := flag.String("prompts", "bench/prompts", "Path to prompt corpus directory")
	resultsDir := flag.String("results", "", "Path to model results directory (required)")
	outputPath := flag.String("output", "", "Output report file path (stdout if empty)")
	format := flag.String("format", "table", "Output format: table, json, or csv")
	modelName := flag.String("model", "unknown", "Model name for the report")
	filterOWASP := flag.String("filter-owasp", "", "Filter by OWASP category (e.g., A03)")
	filterLang := flag.String("filter-lang", "", "Filter by language (e.g., python)")

	flag.Parse()

	if *resultsDir == "" {
		fmt.Fprintf(os.Stderr, "error: --results is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Load prompts
	prompts, err := eval.LoadPrompts(*promptsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading prompts: %v\n", err)
		os.Exit(1)
	}

	// Apply filters
	if *filterOWASP != "" || *filterLang != "" {
		prompts = eval.FilterPrompts(prompts, *filterOWASP, *filterLang, "")
	}

	fmt.Fprintf(os.Stderr, "Loaded %d prompts from %s\n", len(prompts), *promptsDir)

	// Load samples
	samples, err := eval.LoadSamples(*resultsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading samples: %v\n", err)
		os.Exit(1)
	}

	// Filter samples by language if specified
	if *filterLang != "" {
		var filtered []eval.GeneratedSample
		for _, s := range samples {
			if strings.EqualFold(s.Language, *filterLang) {
				filtered = append(filtered, s)
			}
		}
		samples = filtered
	}

	fmt.Fprintf(os.Stderr, "Loaded %d samples from %s\n", len(samples), *resultsDir)

	if len(samples) == 0 {
		fmt.Fprintf(os.Stderr, "error: no samples found\n")
		os.Exit(1)
	}

	// Set model name on samples
	for i := range samples {
		if samples[i].Model == "" {
			samples[i].Model = *modelName
		}
	}

	// Score all samples
	fmt.Fprintf(os.Stderr, "Scoring %d samples...\n", len(samples))
	results := eval.ScoreSamples(prompts, samples)

	// Aggregate
	report := eval.AggregateModelWithPrompts(*modelName, prompts, results)

	// Format output
	var output string
	switch strings.ToLower(*format) {
	case "json":
		output, err = eval.FormatJSON(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error formatting JSON: %v\n", err)
			os.Exit(1)
		}
	case "csv":
		output = eval.FormatCSV(report)
	default:
		output = eval.FormatTable(report)
	}

	// Write output to file or stdout
	if *outputPath == "" {
		fmt.Print(output)
		return
	}

	// Sanitize output path: resolve to absolute and check containment
	cleaned := filepath.Clean(*outputPath)
	absOutput, err := filepath.Abs(cleaned)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving output path: %v\n", err)
		os.Exit(1)
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting working directory: %v\n", err)
		os.Exit(1)
	}
	if !strings.HasPrefix(absOutput, filepath.Clean(cwd)) {
		fmt.Fprintf(os.Stderr, "error: output path is outside working directory\n")
		os.Exit(1)
	}

	// Write the report. Parent directory must already exist.
	if err := os.WriteFile(absOutput, []byte(output), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing output (ensure parent directory exists): %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Report written to %s\n", absOutput)
}
