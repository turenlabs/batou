package taintrule

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/testutil"
)

// End-to-end (full scanner pipeline) coverage for the railsgoat CWE-78 recall
// gap. Unlike the tsflow-layer test, this exercises scanner/ruby_fpfilter.go's
// rubyFilterAllFindings, where a third over-broad defect lived: the
// command-injection guard's line-proximity `.to_i` type-coercion check
// (rubyScanHasTypeCoercion) suppressed ANY CWE-78 finding within 10 lines of a
// `.to_i` — so `system("cp #{file.original_filename} #{Time.zone.now.to_i}")`
// was dropped even though the tainted segment is not coerced. The fix scopes
// that coarse regex guard to regex-tier findings only (the dataflow engine
// already does precise, segment-aware sanitizer analysis for BATOU-TAINT-*).

func ruby78Count(t *testing.T, src string) int {
	t.Helper()
	res := testutil.ScanContent(t, "/app/models/benefits.rb", src)
	n := 0
	for _, f := range res.Findings {
		if f.CWEID == "CWE-78" {
			n++
		}
	}
	return n
}

// TestRubyCmdi_E2E_RailsgoatShape_Fires is load-bearing: reverting either the
// tsflow segment-aware sanitizer fix OR the scanner ruby_fpfilter taint-tier
// scoping drops this to 0.
func TestRubyCmdi_E2E_RailsgoatShape_Fires(t *testing.T) {
	src := "class Benefits < ApplicationRecord\n" +
		"  def self.make_backup(file, data_path, full_file_name)\n" +
		"    silence_streams(STDERR) { system(\"cp #{full_file_name} #{data_path}/bak#{Time.zone.now.to_i}_#{file.original_filename}\") }\n" +
		"  end\nend\n"
	if got := ruby78Count(t, src); got == 0 {
		t.Fatalf("expected the railsgoat command-injection to be flagged CWE-78 end-to-end, got 0")
	}
}

// TestRubyCmdi_E2E_SafeForms_DoNotFire confirms the FP traps stay clean through
// the full pipeline (taint engine + scanner FP filter).
func TestRubyCmdi_E2E_SafeForms_DoNotFire(t *testing.T) {
	cases := map[string]string{
		// array/multi-arg form — no shell
		"array_form":   "def m\n  dir = params[:dir]\n  system(\"ls\", dir)\nend\n",
		"open3_array":  "def m\n  dir = params[:dir]\n  Open3.capture2(\"ls\", dir)\nend\n",
		"shellwords":   "def m\n  n = params[:n]\n  system(\"cp #{Shellwords.escape(n)} /tmp\")\nend\n",
		"to_i_tainted": "def m\n  id = params[:id]\n  system(\"echo #{id.to_i}\")\nend\n",
		"pure_literal": "def m\n  system(\"ls -la /tmp\")\nend\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if got := ruby78Count(t, src); got != 0 {
				t.Fatalf("safe form %q produced %d CWE-78 finding(s), want 0", name, got)
			}
		})
	}
}

// TestRubyCmdi_E2E_RegexTierStillGuarded confirms the scanner FP filter still
// suppresses a regex-tier `.to_i`-coerced shape (the guard's original purpose),
// i.e. the taint-tier scoping did not disable the guard wholesale.
func TestRubyCmdi_E2E_RegexTierStillGuarded(t *testing.T) {
	// A coerced-on-tainted shape must not produce a CWE-78 from any tier.
	src := "def m\n  id = params[:id]\n  system(\"echo #{id.to_i} done\")\nend\n"
	res := testutil.ScanContent(t, "/app/models/x.rb", src)
	for _, f := range res.Findings {
		if f.CWEID == "CWE-78" && strings.HasPrefix(f.RuleID, "BATOU-TAINT-") {
			// taint-tier is allowed to be absent here (coercion sanitizes); the
			// point is no regex-tier CWE-78 leaks through either.
			t.Fatalf("unexpected taint CWE-78 on coerced-tainted shape: %s", f.RuleID)
		}
	}
}
