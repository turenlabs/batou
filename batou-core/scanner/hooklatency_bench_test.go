// hooklatency_bench_test.go — in-process write-time latency benchmarks.
//
// Batou's product thesis is write-time blocking: every agent Write/Edit costs
// two full hook invocations (PreToolUse + PostToolUse), each running the
// complete scanner.Scan pipeline (regex rules, tree-sitter AST, taint, call
// graph load/update/save). These benchmarks measure the in-process cost of
// one such pipeline run on representative single files synthesized from the
// committed testdata fixtures, at three sizes (~100 / ~1k / ~5k LOC) across
// four languages. Process-level numbers (fork+exec, JSON I/O, MB-scale call
// graph load) are measured separately by `make bench-hook`
// (tools/bench_hook.py).
//
// Run with:
//
//	CGO_ENABLED=1 go test -run '^$' -bench 'BenchmarkHookPipeline' -benchtime 3x ./batou-core/scanner/
//
// Reference numbers (2026-06-09, Apple M5 Pro, darwin/arm64, -benchtime 20x,
// sequential single-file scans — full output in the PR that added this file):
//
//	go/small          ~7.0 ms/op   go/medium          ~50 ms/op   go/large          ~210 ms/op
//	python/small      ~7.4 ms/op   python/medium      ~58 ms/op   python/large      ~308 ms/op
//	javascript/small  ~5.1 ms/op   javascript/medium  ~41 ms/op   javascript/large  ~217 ms/op
//	java/small        ~6.8 ms/op   java/medium        ~65 ms/op   java/large        ~333 ms/op
//
// End-to-end (same machine, `make bench-hook`, N=20, 1k-LOC Go event): one
// process invocation p50 ~82-91 ms cold and warm (1.1 MB callgraph adds only
// ~3-8 ms p50), so a Write's PreToolUse+PostToolUse pair costs ~180 ms p50 —
// process startup dominates the in-process pipeline cost for medium files.
//
// These are in-process pipeline costs only; the end-to-end hook adds process
// startup and stdin/stdout JSON handling (see `make bench-hook` for p50/p95).
package scanner_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/hook"
	"github.com/turenlabs/batou-core/scanner"
	"github.com/turenlabs/batou-core/testutil"
	"github.com/turenlabs/batou-rules/rules"

	// Blank imports mirror the registration set the scanner test binary
	// already uses elsewhere in this package (rule categories, the four
	// analyzers exercised by these benchmarks, and the taint engine), so
	// these benchmarks keep working even if other test files shed imports.
	_ "github.com/turenlabs/batou-core/analyzer/goast"
	_ "github.com/turenlabs/batou-core/analyzer/javaast"
	_ "github.com/turenlabs/batou-core/analyzer/jsast"
	_ "github.com/turenlabs/batou-core/analyzer/pyast"
	_ "github.com/turenlabs/batou-core/taint/languages"
	_ "github.com/turenlabs/batou-core/taintrule"
	_ "github.com/turenlabs/batou-rules/rules/auth"
	_ "github.com/turenlabs/batou-rules/rules/crypto"
	_ "github.com/turenlabs/batou-rules/rules/generic"
	_ "github.com/turenlabs/batou-rules/rules/golang"
	_ "github.com/turenlabs/batou-rules/rules/injection"
	_ "github.com/turenlabs/batou-rules/rules/java"
	_ "github.com/turenlabs/batou-rules/rules/jsts"
	_ "github.com/turenlabs/batou-rules/rules/python"
	_ "github.com/turenlabs/batou-rules/rules/secrets"
	_ "github.com/turenlabs/batou-rules/rules/ssrf"
	_ "github.com/turenlabs/batou-rules/rules/traversal"
	_ "github.com/turenlabs/batou-rules/rules/validation"
	_ "github.com/turenlabs/batou-rules/rules/xss"
)

// hookBenchSize defines one representative file size, in target lines of code.
type hookBenchSize struct {
	name      string
	targetLOC int
}

var hookBenchSizes = []hookBenchSize{
	{"small", 100},
	{"medium", 1000},
	{"large", 5000},
}

// hookBenchLang describes how to synthesize a representative single file for
// one language from the committed fixtures under testdata/fixtures/.
type hookBenchLang struct {
	label    string
	wantLang rules.Language // expected DetectLanguage result for fileName
	fileName string         // synthetic file name used in the hook event
	seeds    []string       // fixture paths relative to testdata/fixtures/
}

// Seeds deliberately mix vulnerable and safe fixtures so the synthesized file
// behaves like real application code: some findings fire, most lines are
// clean. Picking only vulnerable seeds would overstate dedup/hints cost;
// only safe seeds would understate rule-match cost.
var hookBenchLangs = []hookBenchLang{
	{
		label:    "go",
		wantLang: rules.LangGo,
		fileName: "handler.go",
		seeds: []string{
			"go/vulnerable/command_injection.go",
			"go/safe/sqli_parameterized.go",
			"go/vulnerable/file_read_traversal.go",
			"go/safe/crypto_strong.go",
			"go/vulnerable/ldap_injection.go",
		},
	},
	{
		label:    "python",
		wantLang: rules.LangPython,
		fileName: "views.py",
		seeds: []string{
			"python/vulnerable/sqli_format.py",
			"python/safe/sqli_parameterized.py",
			"python/vulnerable/command_injection.py",
			"python/safe/path_safe.py",
			"python/vulnerable/weak_crypto.py",
		},
	},
	{
		label:    "javascript",
		wantLang: rules.LangJavaScript,
		fileName: "routes.js",
		seeds: []string{
			"javascript/vulnerable/app_sqli.js",
			"javascript/safe/app_sqli_fixed.js",
			"javascript/vulnerable/app_xss.js",
			"javascript/safe/prototype_safe.js",
			"javascript/vulnerable/app_ssrf.js",
		},
	},
	{
		label:    "java",
		wantLang: rules.LangJava,
		fileName: "Handlers.java",
		seeds: []string{
			"java/vulnerable/SqliBasic.java",
			"java/safe/SqliPrepared.java",
			"java/vulnerable/XssReflected.java",
			"java/vulnerable/CommandInjection.java",
		},
	},
}

// splitFixtureHeader splits fixture content into a header (the leading
// package/import/comment preamble) and a body (everything else). When
// multiple fixture bodies are concatenated under a single header the result
// stays syntactically parseable for every grammar used here: duplicate
// top-level functions/classes are a type-check error, not a parse error, and
// neither go/parser nor tree-sitter type-checks.
func splitFixtureHeader(lang, content string) (header, body string) {
	lines := strings.Split(content, "\n")
	inImportBlock := false
	i := 0
	for ; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if inImportBlock {
			if trimmed == ")" {
				inImportBlock = false
			}
			continue
		}
		if trimmed == "" {
			continue
		}
		isHeader := false
		switch lang {
		case "go":
			switch {
			case strings.HasPrefix(trimmed, "//"),
				strings.HasPrefix(trimmed, "package "),
				strings.HasPrefix(trimmed, "import "):
				isHeader = true
			}
			if trimmed == "import (" {
				inImportBlock = true
				continue
			}
		case "python":
			switch {
			case strings.HasPrefix(trimmed, "#"),
				strings.HasPrefix(trimmed, "import "),
				strings.HasPrefix(trimmed, "from "):
				isHeader = true
			}
		case "javascript":
			switch {
			case strings.HasPrefix(trimmed, "//"),
				strings.HasPrefix(trimmed, "import "),
				strings.HasPrefix(trimmed, "const ") && strings.Contains(trimmed, "require("):
				isHeader = true
			}
		case "java":
			switch {
			case strings.HasPrefix(trimmed, "//"),
				strings.HasPrefix(trimmed, "package "),
				strings.HasPrefix(trimmed, "import "):
				isHeader = true
			}
		}
		if !isHeader {
			break
		}
	}
	return strings.Join(lines[:i], "\n"), strings.Join(lines[i:], "\n")
}

// synthesizeBenchFile builds a single representative file of roughly
// targetLOC lines: the first seed contributes its header (package/imports),
// then seed bodies are appended round-robin until the target is reached.
// The result can overshoot by up to one seed body (~40 lines).
func synthesizeBenchFile(tb testing.TB, lang hookBenchLang, targetLOC int) string {
	tb.Helper()

	type seedParts struct{ header, body string }
	var seeds []seedParts
	for _, rel := range lang.seeds {
		data, err := os.ReadFile(filepath.Join(testutil.FixtureDir(), rel))
		if err != nil {
			tb.Fatalf("loading bench seed fixture %q: %v", rel, err)
		}
		h, b := splitFixtureHeader(lang.label, string(data))
		seeds = append(seeds, seedParts{header: h, body: b})
	}

	var sb strings.Builder
	loc := 0
	write := func(s string) {
		sb.WriteString(s)
		loc += strings.Count(s, "\n")
	}
	write(seeds[0].header)
	write("\n")
	for i := 0; loc < targetLOC; i++ {
		body := seeds[i%len(seeds)].body
		write("\n")
		write(body)
		if !strings.HasSuffix(body, "\n") {
			write("\n")
		}
	}
	return sb.String()
}

// benchHookInput builds the PreToolUse Write event the hook receives from
// Claude Code, rooted in an isolated temp project dir so the call-graph
// load/update/save phase runs for real without polluting the repo.
func benchHookInput(cwd string, lang hookBenchLang, content string) *hook.Input {
	return &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		SessionID:     "hook-latency-bench",
		Cwd:           cwd,
		ToolInput: hook.ToolInput{
			FilePath: filepath.Join(cwd, "src", lang.fileName),
			Content:  content,
		},
	}
}

// BenchmarkHookPipeline measures one full in-process scanner.Scan — the work
// a single hook invocation performs after JSON decode — per language and
// file size. ns/op here is the floor for write-time latency; the end-to-end
// hook (process spawn + graph JSON on disk) is measured by `make bench-hook`.
func BenchmarkHookPipeline(b *testing.B) {
	for _, lang := range hookBenchLangs {
		for _, size := range hookBenchSizes {
			content := synthesizeBenchFile(b, lang, size.targetLOC)
			b.Run(lang.label+"/"+size.name, func(b *testing.B) {
				cwd := b.TempDir()
				input := benchHookInput(cwd, lang, content)
				b.ReportAllocs()
				b.SetBytes(int64(len(content)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					scanner.Scan(input)
				}
				b.StopTimer()
				b.ReportMetric(float64(strings.Count(content, "\n")), "loc")
			})
		}
	}
}

// TestHookPipelineBenchCorpus guards the benchmark corpus itself: every
// synthesized file must be scannable end-to-end (correct language detection,
// no panic/timeout sentinel findings) and the vulnerable-seeded content must
// actually produce findings — otherwise the benchmark would silently measure
// an early-exit path instead of the full pipeline.
func TestHookPipelineBenchCorpus(t *testing.T) {
	if raceDetectorEnabled {
		t.Skip("timing-sensitive corpus guard: -race inflates rule wall-time past the scanner's 10s timeout on CI hardware (BATOU-TIMEOUT fires for instrumentation reasons, not scan degradation)")
	}
	for _, lang := range hookBenchLangs {
		for _, size := range hookBenchSizes {
			lang, size := lang, size
			t.Run(lang.label+"/"+size.name, func(t *testing.T) {
				content := synthesizeBenchFile(t, lang, size.targetLOC)
				loc := strings.Count(content, "\n")
				if loc < size.targetLOC {
					t.Fatalf("synthesized file has %d LOC, want >= %d", loc, size.targetLOC)
				}

				cwd := t.TempDir()
				input := benchHookInput(cwd, lang, content)
				result := scanner.Scan(input)

				if result.Language != lang.wantLang {
					t.Fatalf("language detected as %q, want %q for %s", result.Language, lang.wantLang, lang.fileName)
				}
				for _, f := range result.Findings {
					if f.RuleID == "BATOU-TIMEOUT" || f.RuleID == "BATOU-PANIC" {
						t.Fatalf("scan degraded: %s fired on synthesized %s/%s corpus", f.RuleID, lang.label, size.name)
					}
				}
				if len(result.Findings) == 0 {
					t.Fatalf("no findings on vulnerable-seeded %s/%s corpus — benchmark would measure an early-exit path", lang.label, size.name)
				}
			})
		}
	}
}
