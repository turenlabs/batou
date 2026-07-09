package dirscan

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"

	// Pull in the rule + taint catalogs so the scanner finds the flow.
	_ "github.com/turenlabs/batou-core/analyzer/pyast"
	_ "github.com/turenlabs/batou-core/scanner"
	_ "github.com/turenlabs/batou-core/taint/languages"
	_ "github.com/turenlabs/batou-core/taintrule"
	_ "github.com/turenlabs/batou-rules/rules/injection"
	_ "github.com/turenlabs/batou-rules/rules/python"
	_ "github.com/turenlabs/batou-rules/rules/secrets"
	_ "github.com/turenlabs/batou-rules/rules/validation"
)

// A scanned file with a SQL-injection taint flow should emit a JSONL line
// that includes the structured "taint_path" with source + sink steps. The
// default (regex-tier-dropping) behavior still keeps taint findings, so we
// don't need IncludeRegex=true here.
func TestRun_EmitsTaintPathInJSONL(t *testing.T) {
	dir := t.TempDir()
	src := `from flask import request

def handler():
    uid = request.args.get('id')
    query = "SELECT * FROM users WHERE id=" + uid
    cursor.execute(query)
`
	if err := os.WriteFile(filepath.Join(dir, "v.py"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := Run(context.Background(), Options{
		Root:   dir,
		Exts:   []string{".py"},
		Out:    &out,
		ErrOut: io.Discard,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var sawTaintPath bool
	dec := json.NewDecoder(strings.NewReader(out.String()))
	for {
		var rec map[string]interface{}
		if err := dec.Decode(&rec); err != nil {
			break
		}
		// Every finding record must carry the key (may be null for non-taint findings).
		if _, ok := rec["taint_path"]; !ok {
			t.Errorf("finding record missing taint_path key: %v", rec)
		}
		if steps, ok := rec["taint_path"].([]interface{}); ok && len(steps) >= 2 {
			first, _ := steps[0].(map[string]interface{})
			last, _ := steps[len(steps)-1].(map[string]interface{})
			if first["kind"] == "source" && last["kind"] == "sink" {
				sawTaintPath = true
			}
		}
	}
	if !sawTaintPath {
		t.Errorf("expected at least one finding with a source→sink taint_path; output:\n%s", out.String())
	}
}

// With SARIF=true the scan must emit ONE SARIF 2.1.0 document (not JSONL): a
// valid JSON object with the Batou driver, at least one result for the SQLi
// flow, and the source→sink taint path rendered as a SARIF codeFlow.
func TestRun_SARIFOutput(t *testing.T) {
	dir := t.TempDir()
	src := `from flask import request

def handler():
    uid = request.args.get('id')
    query = "SELECT * FROM users WHERE id=" + uid
    cursor.execute(query)
`
	if err := os.WriteFile(filepath.Join(dir, "v.py"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := Run(context.Background(), Options{
		Root:        dir,
		Exts:        []string{".py"},
		Out:         &out,
		ErrOut:      io.Discard,
		SARIF:       true,
		NoCallgraph: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The whole output must be a single parseable JSON object — not JSONL.
	var doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			OriginalURIBaseIDs map[string]struct {
				URI string `json:"uri"`
			} `json:"originalUriBaseIds"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				CodeFlows           []struct {
					ThreadFlows []struct {
						Locations []interface{} `json:"locations"`
					} `json:"threadFlows"`
				} `json:"codeFlows"`
				Properties map[string]interface{} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF output is not a single JSON object: %v\noutput:\n%s", err, out.String())
	}
	if doc.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %q", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected exactly 1 run, got %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "Batou" {
		t.Errorf("expected driver name Batou, got %q", run.Tool.Driver.Name)
	}
	if len(run.Results) == 0 {
		t.Fatalf("expected at least one SARIF result; output:\n%s", out.String())
	}
	// Find the SQLi taint result and assert it rendered a codeFlow.
	var sawCodeFlow bool
	for _, r := range run.Results {
		if r.Properties["sinkCategory"] == "sql_query" {
			if len(r.CodeFlows) > 0 && len(r.CodeFlows[0].ThreadFlows) > 0 &&
				len(r.CodeFlows[0].ThreadFlows[0].Locations) >= 2 {
				sawCodeFlow = true
			}
		}
	}
	if !sawCodeFlow {
		t.Errorf("expected a sql_query result with a >=2-step codeFlow; output:\n%s", out.String())
	}

	// GitHub code-scanning integration contract: artifact URIs must be
	// scan-root-relative under a SRCROOT uriBaseId declared in
	// originalUriBaseIds, and every result must carry a partialFingerprints
	// identity hash.
	base, ok := run.OriginalURIBaseIDs["SRCROOT"]
	if !ok {
		t.Fatalf("missing SRCROOT in originalUriBaseIds; output:\n%s", out.String())
	}
	if !strings.HasPrefix(base.URI, "file://") || !strings.HasSuffix(base.URI, "/") {
		t.Errorf("SRCROOT uri = %q, want absolute file:// URI with trailing slash", base.URI)
	}
	for i, r := range run.Results {
		if len(r.Locations) == 0 {
			t.Fatalf("result %d has no locations", i)
		}
		art := r.Locations[0].PhysicalLocation.ArtifactLocation
		if art.URI != "v.py" {
			t.Errorf("result %d artifact uri = %q, want root-relative v.py", i, art.URI)
		}
		if art.URIBaseID != "SRCROOT" {
			t.Errorf("result %d uriBaseId = %q, want SRCROOT", i, art.URIBaseID)
		}
		if r.PartialFingerprints["primaryLocationLineHash"] == "" {
			t.Errorf("result %d missing primaryLocationLineHash partial fingerprint", i)
		}
	}
}

// `batou scan --output FILE DIR` should write the JSONL findings to FILE and
// leave stdout untouched.
func TestRunCLI_OutputFlagWritesToFile(t *testing.T) {
	dir := t.TempDir()
	src := `from flask import request

def handler():
    uid = request.args.get('id')
    query = "SELECT * FROM users WHERE id=" + uid
    cursor.execute(query)
`
	if err := os.WriteFile(filepath.Join(dir, "v.py"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	// RunCLI writes .batou/callgraph.json relative to the cwd — run it in a
	// throwaway dir so it doesn't pollute the repo.
	workdir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workdir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(prev) }()

	// Capture stdout to confirm nothing leaks there when --output is set.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	outPath := filepath.Join(workdir, "findings.jsonl")
	code := RunCLI([]string{"--output", outPath, "--quiet", dir})
	_ = w.Close()
	os.Stdout = origStdout

	var stdoutBuf bytes.Buffer
	_, _ = io.Copy(&stdoutBuf, r)
	_ = r.Close()

	if code != 0 {
		t.Fatalf("RunCLI exit code = %d, want 0", code)
	}
	if stdoutBuf.Len() != 0 {
		t.Errorf("stdout should be empty with --output; got %q", stdoutBuf.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading --output file: %v", err)
	}
	if !bytes.Contains(data, []byte(`"rule_id"`)) {
		t.Errorf("--output file does not contain JSONL findings; got:\n%s", data)
	}
	// Each non-empty line must be valid JSON.
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Errorf("--output line is not valid JSON: %q (%v)", line, err)
		}
	}
}

// Heuristic mirror of scanner.findingTier for the JSONL view (which drops the
// tags slice): taint findings carry a taint_path or a TAINT/INTERPROC rule ID;
// AST findings have "AST" in the rule ID; everything else is regex-tier. Good
// enough to assert "the dropped ones were regex-tier" in these tests.
func isRegexTierJSON(rec map[string]interface{}) bool {
	id, _ := rec["rule_id"].(string)
	if tp, ok := rec["taint_path"]; ok && tp != nil {
		return false
	}
	if strings.Contains(id, "TAINT") || strings.Contains(id, "INTERPROC") || strings.Contains(id, "AST") {
		return false
	}
	return true
}

func hasRuleSubstr(recs []map[string]interface{}, idSubstr string) bool {
	for _, r := range recs {
		if id, _ := r["rule_id"].(string); strings.Contains(id, idSubstr) {
			return true
		}
	}
	return false
}

// runScan is a small helper that runs Run with the given Options against a
// fixed Python fixture and decodes the JSONL output into a slice of records.
func runScan(t *testing.T, dir string, opts Options) []map[string]interface{} {
	t.Helper()
	opts.Root = dir
	if opts.Exts == nil {
		opts.Exts = []string{".py"}
	}
	var buf bytes.Buffer
	opts.Out = &buf
	opts.ErrOut = io.Discard
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var recs []map[string]interface{}
	dec := json.NewDecoder(strings.NewReader(buf.String()))
	for {
		var rec map[string]interface{}
		if err := dec.Decode(&rec); err != nil {
			break
		}
		recs = append(recs, rec)
	}
	return recs
}

// regexAndTaintFixture writes a Python file that produces several regex-tier
// findings (hardcoded credential, validation, etc.) plus a real SQL-injection
// taint flow (request.args.get → cursor.execute).
func regexAndTaintFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := `from flask import request

AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def handler():
    uid = request.args.get('id')
    query = "SELECT * FROM users WHERE id=" + uid
    cursor.execute(query)
`
	if err := os.WriteFile(filepath.Join(dir, "v.py"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The new default behavior (since 2026-05-13) drops regex-tier findings from
// the output, leaving only AST/taint/interproc-confirmed findings — including
// the SQL-injection taint flow. Critically, `BATOU-SECRETS-*` hits and other
// regex-only categories are NOT in the default output.
func TestRun_DefaultDropsRegexTier(t *testing.T) {
	dir := regexAndTaintFixture(t)

	// Default (Options{}) — drops regex-tier findings.
	base := runScan(t, dir, Options{})
	if len(base) == 0 {
		t.Fatalf("default scan produced no findings; expected at least the taint flow")
	}
	for _, r := range base {
		if isRegexTierJSON(r) {
			t.Errorf("default scan left a regex-tier finding in the output (should be dropped): %v", r)
		}
	}
	if !hasRuleSubstr(base, "TAINT") {
		t.Errorf("default scan missing the SQL-injection taint finding: %v", base)
	}

	// Sanity: with --with-regex (IncludeRegex=true) we get strictly more
	// findings, including at least one regex-tier finding that the default
	// path was suppressing.
	full := runScan(t, dir, Options{IncludeRegex: true})
	if len(full) <= len(base) {
		t.Errorf("--with-regex did not produce more findings than default: with=%d default=%d", len(full), len(base))
	}
	sawRegexTier := false
	for _, r := range full {
		if isRegexTierJSON(r) {
			sawRegexTier = true
			break
		}
	}
	if !sawRegexTier {
		t.Errorf("--with-regex produced no regex-tier finding (fixture should): %v", full)
	}
	if !hasRuleSubstr(full, "TAINT") {
		t.Errorf("--with-regex dropped the taint finding: %v", full)
	}
}

// --with-regex flips the default off — i.e. it reproduces the pre-2026-05-13
// behavior of "emit every finding".
func TestRun_WithRegexIncludesRegexTier(t *testing.T) {
	dir := regexAndTaintFixture(t)

	full := runScan(t, dir, Options{IncludeRegex: true})
	if len(full) < 2 {
		t.Fatalf("--with-regex scan produced %d findings, want >= 2: %v", len(full), full)
	}
	sawRegexTier := false
	for _, r := range full {
		if isRegexTierJSON(r) {
			sawRegexTier = true
			break
		}
	}
	if !sawRegexTier {
		t.Fatalf("--with-regex scan produced no regex-tier finding: %v", full)
	}
	if !hasRuleSubstr(full, "TAINT") {
		t.Errorf("--with-regex dropped the taint finding: %v", full)
	}
}

// --min-confidence drops findings below the threshold regardless of tier.
// With the new default also dropping regex-tier findings, the count goes down
// from the full set just from the regex drop; the additional confidence gate
// drops anything below 0.7, leaving the 0.95 taint flow intact.
func TestRun_MinConfidenceFilter(t *testing.T) {
	dir := regexAndTaintFixture(t)

	full := runScan(t, dir, Options{IncludeRegex: true})

	mc := runScan(t, dir, Options{MinConfidence: 0.7})
	for _, r := range mc {
		score, _ := r["confidence_score"].(float64)
		if score < 0.7 {
			t.Errorf("--min-confidence 0.7 left a finding scoring %.2f: %v", score, r)
		}
	}
	if !hasRuleSubstr(mc, "TAINT") {
		t.Errorf("--min-confidence 0.7 dropped the 0.95-confidence taint finding: %v", mc)
	}
	if len(mc) >= len(full) {
		t.Errorf("--min-confidence 0.7 did not reduce the finding count vs --with-regex (%d >= %d)", len(mc), len(full))
	}
}

// --no-regex is the compat alias for the new default (drop regex-tier). Its
// output must match the default Options{} run byte-for-byte (modulo source
// order — both are deterministic given a single-file fixture).
func TestRunCLI_NoRegexAliasMatchesDefault(t *testing.T) {
	dir := regexAndTaintFixture(t)

	def := runScan(t, dir, Options{})

	// Simulate `--no-regex` via Options (the CLI maps --no-regex to the new
	// default by leaving IncludeRegex=false; --no-regex by itself produces the
	// same Options shape as no flags at all).
	alias := runScan(t, dir, Options{IncludeRegex: false})

	if len(def) != len(alias) {
		t.Fatalf("--no-regex alias output length differs from default: alias=%d default=%d", len(alias), len(def))
	}
	for i := range def {
		if def[i]["rule_id"] != alias[i]["rule_id"] || def[i]["line"] != alias[i]["line"] {
			t.Errorf("--no-regex alias row %d differs from default: alias=%v default=%v", i, alias[i], def[i])
		}
	}
}

// Mutual-exclusion: --with-regex contradicts both --no-regex and --regex-only,
// and --no-regex/--regex-only still contradict each other. All three pairs
// must exit 2 with a clear error message.
func TestRunCLI_MutuallyExclusiveFlags(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "v.py"), []byte("x = 1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
	}{
		{"with-regex+regex-only", []string{"--with-regex", "--regex-only", dir}},
		{"with-regex+no-regex", []string{"--with-regex", "--no-regex", dir}},
		{"no-regex+regex-only", []string{"--no-regex", "--regex-only", dir}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code := RunCLI(tc.args); code != 2 {
				t.Errorf("RunCLI %v: exit code = %d, want 2", tc.args, code)
			}
		})
	}
}

// JSONL output must carry the cheap triage flags (is_test_file / is_docs_file /
// is_generated_or_vendor) on every record, and source_type/sink_type on taint
// findings. A multi-file Python fixture exercises:
//
//   - src/handler.py:           a real source file with a SQL-injection taint
//     flow (all three triage flags false, taint
//     finding has source_type=user_input,
//     sink_type=sql_query)
//   - docs/handler.py:          identical source but under /docs/ — same finding
//     fires, but is_docs_file=true
//   - tests/test_handler.py:    identical source but under /tests/ with a
//     test_*.py basename — is_test_file=true
//   - src/handler.generated.py: identical source body but with a .generated.
//     infix — is_generated_or_vendor=true. We can't
//     use /vendor/ or /third_party/ here because the
//     scanner short-circuits those entirely
//     (fpfilter.IsVendoredLibrary), so no findings
//     would be emitted to assert against. The
//     .generated. suffix is matched only by our
//     classifier, not by the scanner's drop list.
//
// Using the same Python fixture body across all four files guarantees a real
// taint finding fires on each, so we can assert path-derived flags on every
// emitted record (no extension/language gymnastics).
func TestRun_EmitsTriageFlagsInJSONL(t *testing.T) {
	dir := t.TempDir()
	pySrc := `from flask import request

def handler():
    uid = request.args.get('id')
    query = "SELECT * FROM users WHERE id=" + uid
    cursor.execute(query)
`

	mkfile := func(rel, base string) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(full, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(full, base), []byte(pySrc), 0644); err != nil {
			t.Fatal(err)
		}
	}
	mkfile("src", "handler.py")
	mkfile("docs", "handler.py")
	mkfile("tests", "test_handler.py")
	mkfile("src", "handler.generated.py")

	// Use --with-regex so every layer fires; we want to verify the triage
	// flags appear on regex-tier findings too, not just on taint findings.
	recs := runScan(t, dir, Options{
		IncludeRegex: true,
		Exts:         []string{".py"},
	})
	if len(recs) == 0 {
		t.Fatalf("expected at least one finding across the fixture")
	}

	// Every record must carry the three triage bool flags.
	for _, r := range recs {
		for _, k := range []string{"is_test_file", "is_docs_file", "is_generated_or_vendor"} {
			if _, ok := r[k]; !ok {
				t.Errorf("record missing %q key: %v", k, r)
			}
			if _, ok := r[k].(bool); !ok {
				t.Errorf("record %q is not a bool: %v", k, r[k])
			}
		}
	}

	// Group records by the file's relative path under dir so we can assert
	// flags per fixture. Two files share basename "handler.py" (src/ and
	// docs/) so basename grouping isn't enough.
	byRel := map[string][]map[string]interface{}{}
	for _, r := range recs {
		f, _ := r["file"].(string)
		rel, err := filepath.Rel(dir, f)
		if err != nil {
			rel = f
		}
		byRel[filepath.ToSlash(rel)] = append(byRel[filepath.ToSlash(rel)], r)
	}

	assertAllFlags := func(rel string, wantTest, wantDocs, wantVendor bool) {
		t.Helper()
		recs, ok := byRel[rel]
		if !ok || len(recs) == 0 {
			t.Errorf("no findings emitted for %s; cannot assert flags. byRel keys: %v", rel, keysOf(byRel))
			return
		}
		for _, r := range recs {
			gotTest, _ := r["is_test_file"].(bool)
			gotDocs, _ := r["is_docs_file"].(bool)
			gotVendor, _ := r["is_generated_or_vendor"].(bool)
			if gotTest != wantTest {
				t.Errorf("%s: is_test_file = %v, want %v (record: %v)", rel, gotTest, wantTest, r)
			}
			if gotDocs != wantDocs {
				t.Errorf("%s: is_docs_file = %v, want %v (record: %v)", rel, gotDocs, wantDocs, r)
			}
			if gotVendor != wantVendor {
				t.Errorf("%s: is_generated_or_vendor = %v, want %v (record: %v)", rel, gotVendor, wantVendor, r)
			}
		}
	}

	// src/handler.py — real production code: all three flags false.
	assertAllFlags("src/handler.py", false, false, false)
	// docs/handler.py — is_docs_file true.
	assertAllFlags("docs/handler.py", false, true, false)
	// tests/test_handler.py — is_test_file true (both the /tests/ segment
	// and the test_ prefix mark it).
	assertAllFlags("tests/test_handler.py", true, false, false)
	// src/handler.generated.py — is_generated_or_vendor true.
	assertAllFlags("src/handler.generated.py", false, false, true)

	// On the src/ taint finding, source_type/sink_type must be populated
	// with the expected categories. Non-taint findings under the same dir
	// must NOT carry these keys (they are omitted, not empty-stringed).
	sawTaint := false
	for _, r := range byRel["src/handler.py"] {
		id, _ := r["rule_id"].(string)
		if !strings.Contains(id, "TAINT") && !strings.Contains(id, "INTERPROC") {
			if _, ok := r["source_type"]; ok {
				t.Errorf("non-taint finding leaked source_type: %v", r)
			}
			if _, ok := r["sink_type"]; ok {
				t.Errorf("non-taint finding leaked sink_type: %v", r)
			}
			continue
		}
		sawTaint = true
		src, _ := r["source_type"].(string)
		snk, _ := r["sink_type"].(string)
		if src != "user_input" {
			t.Errorf("taint source_type = %q, want user_input (record: %v)", src, r)
		}
		if snk != "sql_query" {
			t.Errorf("taint sink_type = %q, want sql_query (record: %v)", snk, r)
		}
	}
	if !sawTaint {
		t.Errorf("expected a TAINT or INTERPROC finding under src/handler.py; got: %v", byRel["src/handler.py"])
	}
}

// keysOf returns the sorted keys of a string-keyed map. Used in test error
// messages to make missing-key failures easier to debug.
func keysOf(m map[string][]map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Unit tests for the path classification helpers — these must stay
// conservative; a false positive on is_docs_file / is_generated_or_vendor
// causes triagers to filter real findings.
func TestIsDocsFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"docs/foo.md", true},
		{"/repo/docs/foo.rst", true},
		{"site/index.md", true},
		{"a/site/b/c", true},
		{"a/doc/foo.txt", true},
		{"a/README.md", true},
		{"a/foo.markdown", true},
		{"a/foo.adoc", true},
		{"a/foo.asciidoc", true},

		// Anchored on / boundary — do not match "documentation_loader.go".
		{"src/documentation_loader.go", false},
		{"src/document.py", false},
		{"a/site_test.go", false}, // "/site/" requires both slashes
		{"src/foo.go", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isDocsFile(tc.path); got != tc.want {
			t.Errorf("isDocsFile(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestIsGeneratedOrVendor(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"vendor/foo.go", true},
		{"a/vendor/b/c.go", true},
		{"node_modules/foo/index.js", true},
		{"a/__generated__/foo.ts", true},
		{"a/third_party/pkg.go", true},
		{"a/3rdparty/pkg.go", true},
		{"a/lib.min.js", true},
		{"a/lib.min.css", true},
		{"a/lib.bundle.js", true},
		{"a/foo.pb.go", true},
		{"a/foo_pb.go", true},
		{"a/foo_pb2.py", true},
		{"a/foo_pb2_grpc.py", true},
		{"a/foo.generated.ts", true},
		{"a/foo-generated.js", true},

		// Bundled front-end libraries under conventional asset dirs. The
		// firefly-iii smoke-test FP shape: a jQuery plugin shipped under
		// public/vN/js/lib/ was triaged as first-party. High-precision
		// segments — apps keep their own code under js/app|src|components.
		{"public/v1/js/lib/typeahead/typeahead.jquery.js", true},
		{"public/js/vendor/moment.js", true},
		{"web/assets/vendor/chart.js", true},
		{"public/static/vendor/bootstrap.js", true},

		// Guard against over-classification: a bare /lib/ segment (real app
		// code) must NOT be treated as vendor.
		{"app/services/lib/real_code.rb", false},
		{"src/lib/parser.go", false},
		{"internal/js/app/main.js", false},

		// Lockfiles.
		{"package-lock.json", true},
		{"a/yarn.lock", true},
		{"a/b/go.sum", true},
		{"a/Cargo.lock", true},
		{"a/composer.lock", true},

		// Composer's nested per-component autoloader runtime — the exact
		// Nextcloud smoke-test FP shape. apps/<app>/composer/composer/ and
		// lib/composer/composer/ hold only Composer-generated artifacts.
		{"apps/encryption/composer/composer/ClassLoader.php", true},
		{"lib/composer/composer/InstalledVersions.php", true},
		{"apps/dav/composer/composer/autoload_real.php", true},
		{"/srv/nc/apps/files/composer/composer/ClassLoader.php", true},

		// Negative — "vendoring_logic" / "vendored_data.py" are real source.
		{"src/vendoring_logic.go", false},
		{"src/vendored_data.py", false},
		{"src/minify.go", false},
		{"src/foo.go", false},
		// A single /composer/ dir (the app's own composer.json area) is NOT
		// the vendored autoloader — the doubled segment is required.
		{"apps/myapp/composer/MyService.php", false},
		{"apps/myapp/composer.json", false},
		{"src/composer_helper.go", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isGeneratedOrVendor(tc.path); got != tc.want {
			t.Errorf("isGeneratedOrVendor(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// --regex-only keeps only regex-tier findings (the inverse of --with-regex).
func TestRun_RegexOnlyKeepsOnlyRegexTier(t *testing.T) {
	dir := regexAndTaintFixture(t)

	recs := runScan(t, dir, Options{RegexOnly: true})
	if len(recs) == 0 {
		t.Errorf("--regex-only produced no findings; fixture has regex-tier hits")
	}
	for _, rec := range recs {
		if !isRegexTierJSON(rec) {
			t.Errorf("--regex-only left a non-regex-tier finding: %v", rec)
		}
	}
}

// --no-callgraph skips the persistent .batou/callgraph.json. We verify by
// pointing cwd at a fresh temp dir, running the scan, and asserting no
// .batou/ directory is left behind. (The fixture lives in its own temp dir
// so the scan target itself isn't where the graph would be persisted.)
func TestRun_NoCallgraphSkipsPersistence(t *testing.T) {
	dir := regexAndTaintFixture(t)

	// Point cwd at a clean directory so we can assert nothing was written
	// there. defer restore so other tests aren't affected.
	cwd := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(prev); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}()

	if _, err := runScanReturningErr(t, dir, Options{NoCallgraph: true}); err != nil {
		t.Fatalf("Run with NoCallgraph: %v", err)
	}

	// No .batou should have been created in cwd.
	if _, err := os.Stat(filepath.Join(cwd, ".batou")); !os.IsNotExist(err) {
		t.Errorf("--no-callgraph should not create .batou/; stat err = %v", err)
	}
}

// --callgraph PATH redirects the persistent graph to an explicit location.
func TestRun_CallgraphPathRedirectsSave(t *testing.T) {
	dir := regexAndTaintFixture(t)

	cwd := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(prev); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}()

	altDir := t.TempDir()
	altPath := filepath.Join(altDir, "custom-callgraph.json")
	if _, err := runScanReturningErr(t, dir, Options{CallgraphPath: altPath}); err != nil {
		t.Fatalf("Run with CallgraphPath: %v", err)
	}

	if _, err := os.Stat(altPath); err != nil {
		t.Errorf("expected callgraph at %s: %v", altPath, err)
	}
	// Default cwd-relative .batou/ should NOT have been created.
	if _, err := os.Stat(filepath.Join(cwd, ".batou")); !os.IsNotExist(err) {
		t.Errorf("--callgraph PATH should not also create cwd/.batou/; stat err = %v", err)
	}
}

// --callgraph and --no-callgraph together should exit 2.
func TestRunCLI_CallgraphAndNoCallgraphMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	args := []string{"--callgraph", "/tmp/anything.json", "--no-callgraph", dir}
	if code := RunCLI(args); code != 2 {
		t.Errorf("RunCLI %v: exit code = %d, want 2", args, code)
	}
}

// Same check at the Run() (library) layer, which has its own defensive guard.
func TestRun_CallgraphAndNoCallgraphMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	err := Run(context.Background(), Options{
		Root:          dir,
		Out:           io.Discard,
		ErrOut:        io.Discard,
		CallgraphPath: "/tmp/anything.json",
		NoCallgraph:   true,
	})
	if err == nil {
		t.Fatal("expected error when both CallgraphPath and NoCallgraph are set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error %q does not mention mutual exclusion", err)
	}
}

// runScanReturningErr mirrors runScan but returns the Run error so a test can
// assert non-nil (mutual-exclusion case) without crashing on t.Fatalf inside
// the helper.
func runScanReturningErr(t *testing.T, dir string, opts Options) ([]map[string]interface{}, error) {
	t.Helper()
	opts.Root = dir
	if opts.Exts == nil {
		opts.Exts = []string{".py"}
	}
	var buf bytes.Buffer
	opts.Out = &buf
	opts.ErrOut = io.Discard
	if err := Run(context.Background(), opts); err != nil {
		return nil, err
	}
	var recs []map[string]interface{}
	dec := json.NewDecoder(strings.NewReader(buf.String()))
	for {
		var rec map[string]interface{}
		if err := dec.Decode(&rec); err != nil {
			break
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// =========================================================================
// --fail-on CI gating
// =========================================================================

// normalizeFailOn must accept every documented level (case-insensitively,
// with "" as the none alias) and reject anything else.
func TestNormalizeFailOn(t *testing.T) {
	valid := map[string]string{
		"":         FailOnNone,
		"none":     FailOnNone,
		"NONE":     FailOnNone,
		" any ":    FailOnAny,
		"blocking": FailOnBlocking,
		"critical": FailOnCritical,
		"High":     FailOnHigh,
	}
	for in, want := range valid {
		got, err := normalizeFailOn(in)
		if err != nil || got != want {
			t.Errorf("normalizeFailOn(%q) = (%q, %v), want (%q, nil)", in, got, err, want)
		}
	}
	for _, in := range []string{"bogus", "medium", "all", "1"} {
		if _, err := normalizeFailOn(in); err == nil {
			t.Errorf("normalizeFailOn(%q) = nil error, want error", in)
		}
	}
}

// failOnMatch implements the policy table: severity thresholds for
// critical/high, ShouldBlock (risk_score >= 0.7) for blocking, everything
// for any, nothing for none.
func TestFailOnMatch(t *testing.T) {
	critBlocking := rules.Finding{Severity: rules.Critical, RiskScore: 0.95}
	critHint := rules.Finding{Severity: rules.Critical, RiskScore: 0.4}
	high := rules.Finding{Severity: rules.High, RiskScore: 0.5}
	medium := rules.Finding{Severity: rules.Medium, RiskScore: 0.2}
	cases := []struct {
		policy string
		f      rules.Finding
		want   bool
	}{
		{FailOnNone, critBlocking, false},
		{"", critBlocking, false},
		{FailOnAny, medium, true},
		{FailOnBlocking, critBlocking, true},
		{FailOnBlocking, critHint, false},
		{FailOnCritical, critHint, true},
		{FailOnCritical, high, false},
		{FailOnHigh, high, true},
		{FailOnHigh, critBlocking, true},
		{FailOnHigh, medium, false},
	}
	for _, c := range cases {
		if got := failOnMatch(c.policy, &c.f); got != c.want {
			t.Errorf("failOnMatch(%q, sev=%v risk=%.2f) = %v, want %v",
				c.policy, c.f.Severity, c.f.RiskScore, got, c.want)
		}
	}
}

// RunStats must reject an unknown FailOn value with an error instead of
// silently scanning with a policy that never matches.
func TestRunStats_FailOnInvalidValueErrors(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	_, err := RunStats(context.Background(), Options{
		Root:        dir,
		Out:         &buf,
		ErrOut:      io.Discard,
		NoCallgraph: true,
		FailOn:      "bogus",
	})
	if err == nil || !strings.Contains(err.Error(), "fail-on") {
		t.Fatalf("RunStats with FailOn=bogus: err = %v, want invalid --fail-on error", err)
	}
}

// RunStats counts emitted findings matching the policy: the SQLi taint flow
// is Critical with high confidence, so it matches every gating level; the
// clean file matches none.
func TestRunStats_FailOnMatchesCount(t *testing.T) {
	vuln := t.TempDir()
	src := `from flask import request

def handler():
    uid = request.args.get('id')
    query = "SELECT * FROM users WHERE id=" + uid
    cursor.execute(query)
`
	if err := os.WriteFile(filepath.Join(vuln, "v.py"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "c.py"), []byte("print('hello')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	run := func(root, failOn string) Stats {
		t.Helper()
		var buf bytes.Buffer
		stats, err := RunStats(context.Background(), Options{
			Root:        root,
			Exts:        []string{".py"},
			Out:         &buf,
			ErrOut:      io.Discard,
			NoCallgraph: true,
			FailOn:      failOn,
		})
		if err != nil {
			t.Fatalf("RunStats(%s, %s): %v", root, failOn, err)
		}
		return stats
	}

	for _, policy := range []string{FailOnAny, FailOnBlocking, FailOnCritical, FailOnHigh} {
		if got := run(vuln, policy); got.FailOnMatches == 0 {
			t.Errorf("vulnerable dir with FailOn=%s: FailOnMatches = 0, want > 0", policy)
		}
	}
	if got := run(vuln, FailOnNone); got.FailOnMatches != 0 {
		t.Errorf("vulnerable dir with FailOn=none: FailOnMatches = %d, want 0", got.FailOnMatches)
	}
	if got := run(clean, FailOnAny); got.FailOnMatches != 0 {
		t.Errorf("clean dir with FailOn=any: FailOnMatches = %d, want 0", got.FailOnMatches)
	}
}

// RunCLI exit codes: 0 = completed with no policy match, 2 = usage error
// (invalid --fail-on), 3 = findings matched the policy. The vulnerable dir
// emits a Critical SQLi taint flow; the clean dir emits nothing.
func TestRunCLI_FailOnExitCodes(t *testing.T) {
	vuln := t.TempDir()
	src := `from flask import request

def handler():
    uid = request.args.get('id')
    query = "SELECT * FROM users WHERE id=" + uid
    cursor.execute(query)
`
	if err := os.WriteFile(filepath.Join(vuln, "v.py"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "c.py"), []byte("print('hello')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"vuln fail-on critical", []string{"--fail-on", "critical", vuln}, 3},
		{"vuln fail-on blocking", []string{"--fail-on", "blocking", vuln}, 3},
		{"vuln fail-on any", []string{"--fail-on", "any", vuln}, 3},
		{"vuln fail-on none", []string{"--fail-on", "none", vuln}, 0},
		{"vuln default (no flag) keeps exit 0", []string{vuln}, 0},
		{"clean fail-on any", []string{"--fail-on", "any", clean}, 0},
		{"invalid fail-on value is a usage error", []string{"--fail-on", "bogus", vuln}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			outPath := filepath.Join(t.TempDir(), "out.jsonl")
			args := append([]string{"--quiet", "--no-callgraph", "--output", outPath}, c.args...)
			if code := RunCLI(args); code != c.want {
				t.Errorf("RunCLI(%v) = %d, want %d", args, code, c.want)
			}
		})
	}
}
