package scanner_test

import (
	"bufio"
	"os"
	"strings"
	"testing"

	_ "github.com/turenlabs/batou-core/taintrule"
	"github.com/turenlabs/batou-core/testutil"
)

const owaspJavaBase = "../../testdata/external/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/"

const owaspJavaCSV = "../../testdata/external/BenchmarkJava/expectedresults-1.2.csv"

// requireOWASPJava skips the calling test when the local-only OWASP
// BenchmarkJava corpus is absent. These are diagnostic tests (they only log
// FN/FP breakdowns, they do not assert); the corpus is gitignored and cloned
// on demand via `make bench-owasp-clone`, so in CI it is not present.
func requireOWASPJava(t *testing.T) {
	if _, err := os.Stat(owaspJavaCSV); err != nil {
		t.Skip("OWASP BenchmarkJava corpus not present; run `make bench-owasp-clone` (local-only)")
	}
}

// cmdiCases reads the expected-results CSV and returns vuln/safe cmdi test names.
func cmdiCases(t *testing.T) (vuln, safe []string) {
	f, err := os.Open(owaspJavaCSV)
	if err != nil {
		t.Fatalf("open csv: %v", err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ",")
		if len(parts) < 4 || parts[1] != "cmdi" {
			continue
		}
		if parts[2] == "true" {
			vuln = append(vuln, parts[0])
		} else {
			safe = append(safe, parts[0])
		}
	}
	return
}

func firesCWE78InDir(t *testing.T, name, dir string) (bool, []string) {
	content, err := os.ReadFile(owaspJavaBase + name + ".java")
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	res := testutil.ScanContentInDir(t, "/app/owasp/"+name+".java", string(content), dir)
	var rules []string
	got := false
	for _, f := range res.Findings {
		rules = append(rules, f.RuleID+"("+f.CWEID+")")
		if f.CWEID == "CWE-78" {
			got = true
		}
	}
	return got, rules
}

// TestCmdiFN lists all cmdi vuln FNs (no CWE-78 finding), isolated per-case.
func TestCmdiFN(t *testing.T) {
	requireOWASPJava(t)
	vuln, _ := cmdiCases(t)
	var fn []string
	for _, name := range vuln {
		got, _ := firesCWE78InDir(t, name, t.TempDir())
		if !got {
			fn = append(fn, name)
		}
	}
	t.Logf("cmdi vuln=%d FN(isolated)=%d", len(vuln), len(fn))
	t.Logf("FN list: %s", strings.Join(fn, " "))
}

// TestCmdiFNShared mimics the real harness: one shared benchDir for all cases.
func TestCmdiFNShared(t *testing.T) {
	requireOWASPJava(t)
	vuln, _ := cmdiCases(t)
	dir := t.TempDir()
	var fn []string
	for _, name := range vuln {
		got, _ := firesCWE78InDir(t, name, dir)
		if !got {
			fn = append(fn, name)
		}
	}
	t.Logf("cmdi vuln=%d FN(shared)=%d", len(vuln), len(fn))
	t.Logf("FN list: %s", strings.Join(fn, " "))
}

// TestCmdiFPDetail dumps all findings for select safe-FP cases.
func TestCmdiFPDetail(t *testing.T) {
	requireOWASPJava(t)
	for _, name := range []string{"BenchmarkTest00396", "BenchmarkTest00158", "BenchmarkTest00814", "BenchmarkTest00558", "BenchmarkTest00559", "BenchmarkTest01353"} {
		content, _ := os.ReadFile(owaspJavaBase + name + ".java")
		res := testutil.ScanContentInDir(t, "/app/owasp/"+name+".java", string(content), t.TempDir())
		t.Logf("=== %s: %d findings ===", name, len(res.Findings))
		for _, f := range res.Findings {
			t.Logf("  rule=%s cwe=%s line=%d conf=%.2f", f.RuleID, f.CWEID, f.LineNumber, f.ConfidenceScore)
		}
	}
}

// TestCmdiFNDetail dumps all findings for each FN case.
func TestCmdiFNDetail(t *testing.T) {
	requireOWASPJava(t)
	for _, name := range []string{"BenchmarkTest02429", "BenchmarkTest02430", "BenchmarkTest01531", "BenchmarkTest01533"} {
		content, _ := os.ReadFile(owaspJavaBase + name + ".java")
		res := testutil.ScanContent(t, "/app/handler/"+name+".java", string(content))
		t.Logf("=== %s: %d findings ===", name, len(res.Findings))
		for _, f := range res.Findings {
			t.Logf("  rule=%s cwe=%s line=%d conf=%.2f", f.RuleID, f.CWEID, f.LineNumber, f.ConfidenceScore)
		}
	}
}

// TestCmdiSafeFP lists all cmdi safe cases that wrongly fire CWE-78 (FP),
// isolated per-case (matches real harness independence).
func TestCmdiSafeFP(t *testing.T) {
	requireOWASPJava(t)
	_, safe := cmdiCases(t)
	var fp []string
	for _, name := range safe {
		got, _ := firesCWE78InDir(t, name, t.TempDir())
		if got {
			fp = append(fp, name)
		}
	}
	t.Logf("cmdi safe=%d FP(isolated)=%d", len(safe), len(fp))
	t.Logf("FP list: %s", strings.Join(fp, " "))
}

// TestCmdiFPMatchedLines prints the CWE-78 finding's matched line for each FP.
func TestCmdiFPMatchedLines(t *testing.T) {
	requireOWASPJava(t)
	_, safe := cmdiCases(t)
	for _, name := range safe {
		content, _ := os.ReadFile(owaspJavaBase + name + ".java")
		lines := strings.Split(string(content), "\n")
		res := testutil.ScanContentInDir(t, "/app/owasp/"+name+".java", string(content), t.TempDir())
		for _, f := range res.Findings {
			if f.CWEID == "CWE-78" {
				ln := ""
				if f.LineNumber-1 >= 0 && f.LineNumber-1 < len(lines) {
					ln = strings.TrimSpace(lines[f.LineNumber-1])
				}
				t.Logf("%s L%d %s: %q", name, f.LineNumber, f.RuleID, ln)
			}
		}
	}
}
