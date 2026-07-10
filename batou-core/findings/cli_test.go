package findings

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it. The CLI helpers print directly to os.Stdout,
// so this is the only way to assert on their output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()

	fn()

	_ = w.Close()
	os.Stdout = orig
	out := <-done
	_ = r.Close()
	return out
}

// chdirTemp changes into a fresh, non-git temp dir so FindRoot() falls back
// to cwd and writes findings into <tmp>/.batou rather than the real repo.
// The original cwd is restored on cleanup.
func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
	return dir
}

// seedStore opens a store at batouDir, applies fn, saves (releasing the
// lock), and returns nothing — the data is now persisted on disk for a
// fresh RunCLI / Open to read back.
func seedStore(t *testing.T, batouDir string, fn func(*Store)) {
	t.Helper()
	s, err := Open(batouDir)
	if err != nil {
		t.Fatalf("seed Open: %v", err)
	}
	fn(s)
	if err := s.Save(); err != nil {
		t.Fatalf("seed Save: %v", err)
	}
}

func TestFormatTime(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"rfc3339", "2026-06-19T12:34:56Z", "2026-06-19"},
		{"date only", "2026-06-19", "2026-06-19"},
		{"empty", "", ""},
		{"leading T has no date", "T12:00:00", "T12:00:00"}, // idx==0, not >0
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatTime(tt.in); got != tt.want {
				t.Errorf("formatTime(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestPrintUsage(t *testing.T) {
	out := captureStdout(t, func() { printUsage() })
	for _, want := range []string{"Usage: batou findings", "--summary", "--suppressed", "--all", "--json", "--help"} {
		if !strings.Contains(out, want) {
			t.Errorf("printUsage output missing %q\n%s", want, out)
		}
	}
}

func TestPrintRecord(t *testing.T) {
	tests := []struct {
		name        string
		rec         *Record
		wantContain []string
		wantOmit    []string
	}{
		{
			name: "active with line number",
			rec: &Record{
				RuleID:        "BATOU-INJ-001",
				FilePath:      "/app/main.go",
				LineNumber:    42,
				Title:         "Command injection",
				SeverityLabel: "CRITICAL",
				Status:        StatusActive,
				FirstSeen:     "2026-06-19T10:00:00Z",
				Count:         3,
			},
			wantContain: []string{"CRITICAL", "BATOU-INJ-001", "Command injection", "/app/main.go:42", "Count: 3", "2026-06-19"},
			wantOmit:    []string{"[suppressed]", "[resolved]", "Reason:"},
		},
		{
			name: "suppressed with reason and no line number",
			rec: &Record{
				RuleID:         "BATOU-SEC-001",
				FilePath:       "/app/config.go",
				LineNumber:     0,
				Title:          "Hardcoded secret",
				SeverityLabel:  "HIGH",
				Status:         StatusSuppressed,
				SuppressReason: "test fixture credential",
				FirstSeen:      "2026-06-18T09:00:00Z",
				Count:          1,
			},
			wantContain: []string{"[suppressed]", "Reason: test fixture credential", "/app/config.go"},
			wantOmit:    []string{":0", "[resolved]"},
		},
		{
			name: "resolved",
			rec: &Record{
				RuleID:        "BATOU-XSS-001",
				FilePath:      "/app/view.go",
				LineNumber:    7,
				Title:         "XSS",
				SeverityLabel: "MEDIUM",
				Status:        StatusResolved,
				FirstSeen:     "2026-06-17T08:00:00Z",
				Count:         2,
			},
			wantContain: []string{"[resolved]", "/app/view.go:7"},
			wantOmit:    []string{"[suppressed]"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := captureStdout(t, func() { printRecord(tt.rec) })
			for _, w := range tt.wantContain {
				if !strings.Contains(out, w) {
					t.Errorf("printRecord output missing %q\n%s", w, out)
				}
			}
			for _, w := range tt.wantOmit {
				if strings.Contains(out, w) {
					t.Errorf("printRecord output should not contain %q\n%s", w, out)
				}
			}
		})
	}
}

func TestOutputSummary_Empty(t *testing.T) {
	s := tempStore(t)
	out := captureStdout(t, func() {
		if code := outputSummary(s); code != 0 {
			t.Errorf("expected exit 0, got %d", code)
		}
	})
	if !strings.Contains(out, "No findings recorded yet.") {
		t.Errorf("expected empty message, got:\n%s", out)
	}
}

func TestOutputSummary_Populated(t *testing.T) {
	s := tempStore(t)

	crit := sampleFinding("BATOU-INJ-001", "/app/a.go", "exec")
	crit.Severity = rules.Critical
	s.Upsert(crit)

	high := sampleFinding("BATOU-INJ-002", "/app/b.go", "eval")
	high.Severity = rules.High
	s.Upsert(high)

	s.UpsertSuppressed(sampleFinding("BATOU-SEC-001", "/app/c.go", "secret"), "fp")

	// Resolve one finding on /app/d.go.
	d := sampleFinding("BATOU-INJ-003", "/app/d.go", "system")
	s.Upsert(d)
	s.MarkResolved("/app/d.go", map[string]bool{})

	out := captureStdout(t, func() {
		if code := outputSummary(s); code != 0 {
			t.Errorf("expected exit 0, got %d", code)
		}
	})

	for _, want := range []string{
		"Batou Findings Summary",
		"Active:     2",
		"Suppressed: 1",
		"Resolved:   1",
		"Total:      4",
		"Active by severity:",
		"CRITICAL  1",
		"HIGH      1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary output missing %q\n%s", want, out)
		}
	}
	// No active LOW/MEDIUM/INFO findings, so those rows should be absent.
	for _, omit := range []string{"MEDIUM ", "LOW ", "INFO "} {
		if strings.Contains(out, omit) {
			t.Errorf("summary output should not list %q\n%s", omit, out)
		}
	}
}

func TestOutputJSON(t *testing.T) {
	s := tempStore(t)
	s.Upsert(sampleFinding("BATOU-INJ-001", "/app/a.go", "exec"))
	s.UpsertSuppressed(sampleFinding("BATOU-SEC-001", "/app/c.go", "secret"), "fp")
	resolvedF := sampleFinding("BATOU-INJ-003", "/app/d.go", "system")
	s.Upsert(resolvedF)
	s.MarkResolved("/app/d.go", map[string]bool{})

	tests := []struct {
		name           string
		showAll        bool
		showSuppressed bool
		wantRuleIDs    []string
		notRuleIDs     []string
	}{
		{"default active only", false, false, []string{"BATOU-INJ-001"}, []string{"BATOU-SEC-001", "BATOU-INJ-003"}},
		{"suppressed only", false, true, []string{"BATOU-SEC-001"}, []string{"BATOU-INJ-001", "BATOU-INJ-003"}},
		{"all", true, false, []string{"BATOU-INJ-001", "BATOU-SEC-001", "BATOU-INJ-003"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				if code := outputJSON(s, tt.showAll, tt.showSuppressed); code != 0 {
					t.Errorf("expected exit 0, got %d", code)
				}
			})
			var records []*Record
			if err := json.Unmarshal([]byte(out), &records); err != nil {
				t.Fatalf("output is not valid JSON: %v\n%s", err, out)
			}
			got := make(map[string]bool)
			for _, r := range records {
				got[r.RuleID] = true
			}
			for _, want := range tt.wantRuleIDs {
				if !got[want] {
					t.Errorf("expected %q in JSON output, got %v", want, got)
				}
			}
			for _, no := range tt.notRuleIDs {
				if got[no] {
					t.Errorf("did not expect %q in JSON output, got %v", no, got)
				}
			}
		})
	}
}

func TestFindRoot_NoGitFallsBackToFileDir(t *testing.T) {
	dir := t.TempDir()
	// Anchor on a file path inside a non-git temp dir → FindRoot uses the
	// file's parent directory and creates .batou under it.
	got, err := FindRoot(dir + "/sub/handler.go")
	if err != nil {
		t.Fatalf("FindRoot: %v", err)
	}
	if !strings.HasSuffix(got, ".batou") {
		t.Errorf("expected .batou suffix, got %q", got)
	}
	if info, statErr := os.Stat(got); statErr != nil || !info.IsDir() {
		t.Errorf("expected .batou dir to be created at %q: %v", got, statErr)
	}
}

func TestFindRoot_NoArgsUsesCwd(t *testing.T) {
	dir := chdirTemp(t)
	got, err := FindRoot()
	if err != nil {
		t.Fatalf("FindRoot: %v", err)
	}
	// In a non-git cwd, the root is the cwd itself. On macOS the temp dir
	// may be symlinked (/var vs /private/var), so compare the basename chain
	// via Stat instead of string equality.
	wantInfo, err := os.Stat(dir + "/.batou")
	if err != nil {
		t.Fatalf("expected .batou under cwd: %v", err)
	}
	gotInfo, err := os.Stat(got)
	if err != nil {
		t.Fatalf("stat FindRoot result: %v", err)
	}
	if !os.SameFile(wantInfo, gotInfo) {
		t.Errorf("FindRoot() = %q, expected the cwd .batou dir %q", got, dir+"/.batou")
	}
}

func TestRunCLI_Help(t *testing.T) {
	chdirTemp(t)
	for _, flag := range []string{"--help", "-h"} {
		out := captureStdout(t, func() {
			if code := RunCLI([]string{flag}); code != 0 {
				t.Errorf("RunCLI(%q) exit = %d, want 0", flag, code)
			}
		})
		if !strings.Contains(out, "Usage: batou findings") {
			t.Errorf("RunCLI(%q) did not print usage:\n%s", flag, out)
		}
	}
}

func TestRunCLI_DefaultEmpty(t *testing.T) {
	chdirTemp(t)
	out := captureStdout(t, func() {
		if code := RunCLI(nil); code != 0 {
			t.Errorf("RunCLI exit = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "No active findings") {
		t.Errorf("expected clean message, got:\n%s", out)
	}
}

func TestRunCLI_DefaultWithActive(t *testing.T) {
	dir := chdirTemp(t)
	batouDir, err := FindRoot()
	if err != nil {
		t.Fatalf("FindRoot: %v", err)
	}
	_ = dir
	seedStore(t, batouDir, func(s *Store) {
		f := sampleFinding("BATOU-INJ-001", "/app/main.go", "exec(cmd)")
		f.Severity = rules.Critical
		f.Title = "OS command injection"
		s.Upsert(f)
	})

	out := captureStdout(t, func() {
		if code := RunCLI(nil); code != 0 {
			t.Errorf("RunCLI exit = %d, want 0", code)
		}
	})
	for _, want := range []string{"Active findings (1)", "BATOU-INJ-001", "OS command injection"} {
		if !strings.Contains(out, want) {
			t.Errorf("RunCLI output missing %q\n%s", want, out)
		}
	}
}

func TestRunCLI_Summary(t *testing.T) {
	chdirTemp(t)
	batouDir, err := FindRoot()
	if err != nil {
		t.Fatalf("FindRoot: %v", err)
	}
	seedStore(t, batouDir, func(s *Store) {
		f := sampleFinding("BATOU-INJ-001", "/app/main.go", "exec(cmd)")
		f.Severity = rules.High
		s.Upsert(f)
	})

	for _, flag := range []string{"--summary", "-s"} {
		out := captureStdout(t, func() {
			if code := RunCLI([]string{flag}); code != 0 {
				t.Errorf("RunCLI(%q) exit = %d, want 0", flag, code)
			}
		})
		if !strings.Contains(out, "Batou Findings Summary") {
			t.Errorf("RunCLI(%q) missing summary header:\n%s", flag, out)
		}
		if !strings.Contains(out, "Active:     1") {
			t.Errorf("RunCLI(%q) missing active count:\n%s", flag, out)
		}
	}
}

func TestRunCLI_Suppressed(t *testing.T) {
	chdirTemp(t)
	batouDir, err := FindRoot()
	if err != nil {
		t.Fatalf("FindRoot: %v", err)
	}

	// Empty case first.
	out := captureStdout(t, func() {
		if code := RunCLI([]string{"--suppressed"}); code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "No suppressed findings.") {
		t.Errorf("expected empty suppressed message, got:\n%s", out)
	}

	// Now seed a suppressed finding.
	seedStore(t, batouDir, func(s *Store) {
		s.UpsertSuppressed(sampleFinding("BATOU-SEC-001", "/app/config.go", "password ="), "test credential")
	})
	out = captureStdout(t, func() {
		if code := RunCLI([]string{"--suppressed"}); code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
	})
	for _, want := range []string{"Suppressed findings (1)", "BATOU-SEC-001", "Reason: test credential"} {
		if !strings.Contains(out, want) {
			t.Errorf("RunCLI --suppressed missing %q\n%s", want, out)
		}
	}
}

func TestRunCLI_All(t *testing.T) {
	chdirTemp(t)
	batouDir, err := FindRoot()
	if err != nil {
		t.Fatalf("FindRoot: %v", err)
	}

	// Empty case.
	out := captureStdout(t, func() {
		if code := RunCLI([]string{"--all"}); code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "No findings recorded yet.") {
		t.Errorf("expected empty --all message, got:\n%s", out)
	}

	// Seed active + suppressed + resolved.
	seedStore(t, batouDir, func(s *Store) {
		s.Upsert(sampleFinding("BATOU-INJ-001", "/app/a.go", "exec"))
		s.UpsertSuppressed(sampleFinding("BATOU-SEC-001", "/app/b.go", "secret"), "fp")
		r := sampleFinding("BATOU-XSS-001", "/app/c.go", "innerHTML")
		s.Upsert(r)
		s.MarkResolved("/app/c.go", map[string]bool{})
	})

	out = captureStdout(t, func() {
		if code := RunCLI([]string{"-a"}); code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
	})
	for _, want := range []string{
		"1 active, 1 suppressed, 1 resolved",
		"BATOU-INJ-001", "BATOU-SEC-001", "BATOU-XSS-001",
		"[suppressed]", "[resolved]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("RunCLI --all missing %q\n%s", want, out)
		}
	}
}

func TestRunCLI_JSON(t *testing.T) {
	chdirTemp(t)
	batouDir, err := FindRoot()
	if err != nil {
		t.Fatalf("FindRoot: %v", err)
	}
	seedStore(t, batouDir, func(s *Store) {
		s.Upsert(sampleFinding("BATOU-INJ-001", "/app/a.go", "exec"))
		s.UpsertSuppressed(sampleFinding("BATOU-SEC-001", "/app/b.go", "secret"), "fp")
	})

	out := captureStdout(t, func() {
		if code := RunCLI([]string{"--json"}); code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
	})
	var records []*Record
	if err := json.Unmarshal([]byte(out), &records); err != nil {
		t.Fatalf("RunCLI --json output not valid JSON: %v\n%s", err, out)
	}
	if len(records) != 1 || records[0].RuleID != "BATOU-INJ-001" {
		t.Errorf("expected only the active finding in default --json, got %+v", records)
	}

	// --json --all should include the suppressed one too.
	out = captureStdout(t, func() {
		if code := RunCLI([]string{"--json", "--all"}); code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
	})
	records = nil
	if err := json.Unmarshal([]byte(out), &records); err != nil {
		t.Fatalf("RunCLI --json --all output not valid JSON: %v\n%s", err, out)
	}
	if len(records) != 2 {
		t.Errorf("expected 2 records for --json --all, got %d", len(records))
	}
}
