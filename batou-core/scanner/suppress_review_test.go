// Regression tests for BATOU-SUPPRESS-REVIEW behaviour: the rule fires only
// when the agent adds a suppress directive without a documented reason.
// Directives carrying `-- <reason>` are trusted self-corrections and stay
// silent, letting agents resolve false positives autonomously.
package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/hook"
	"github.com/turenlabs/batou-core/reporter"
)

func TestDirectiveHasReason(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"// batou:ignore injection -- parameterized", true},
		{"# batou:ignore file_read -- local CLI utility", true},
		{"// batou:ignore-start xss -- pre-validated", true},
		{"# batou:ignore file_read", false},
		{"// batou:ignore injection", false},
		{"// batou:ignore-end", false},
		{"// batou:ignore injection --", false}, // empty reason after --
		{"// batou:ignore injection --   ", false},
		{"// BATOU:IGNORE INJECTION -- REASON", true}, // case-insensitive
		{"nothing here", false},
	}
	for _, tc := range cases {
		if got := directiveHasReason(tc.line); got != tc.want {
			t.Errorf("directiveHasReason(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

func TestDetectNewSuppressDirectives_SkipsReasonedDirective(t *testing.T) {
	// Agent self-corrects by adding a suppress directive WITH a reason —
	// SUPPRESS-REVIEW must NOT fire. Previously this blocked autonomous
	// work because the review finding was unsuppressible and High-severity.
	dir := t.TempDir()
	filePath := filepath.Join(dir, "handler.py")
	original := "def handler():\n    os.system(cmd)\n"
	_ = os.WriteFile(filePath, []byte(original), 0644)

	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Edit",
		ToolInput: hook.ToolInput{
			FilePath:  filePath,
			OldString: "    os.system(cmd)",
			NewString: "    # batou:ignore injection -- cmd is a constant literal, not user input\n    os.system(cmd)",
		},
	}
	result := &reporter.ScanResult{FilePath: filePath}
	newContent := "def handler():\n    # batou:ignore injection -- cmd is a constant literal, not user input\n    os.system(cmd)\n"
	detectNewSuppressDirectives(input, newContent, result)

	for _, f := range result.Findings {
		if f.RuleID == "BATOU-SUPPRESS-REVIEW" {
			t.Errorf("reasoned directive should not trigger SUPPRESS-REVIEW; got %+v", f)
		}
	}
}

func TestDetectNewSuppressDirectives_FiresOnBareDirective(t *testing.T) {
	// Agent adds a suppress directive WITHOUT a reason — nudge them to
	// document it. Guardrail: accountability survives.
	dir := t.TempDir()
	filePath := filepath.Join(dir, "handler.py")
	original := "def handler():\n    os.system(cmd)\n"
	_ = os.WriteFile(filePath, []byte(original), 0644)

	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Edit",
		ToolInput: hook.ToolInput{
			FilePath:  filePath,
			OldString: "    os.system(cmd)",
			NewString: "    # batou:ignore injection\n    os.system(cmd)",
		},
	}
	result := &reporter.ScanResult{FilePath: filePath}
	newContent := "def handler():\n    # batou:ignore injection\n    os.system(cmd)\n"
	detectNewSuppressDirectives(input, newContent, result)

	var found *string
	for _, f := range result.Findings {
		if f.RuleID == "BATOU-SUPPRESS-REVIEW" {
			desc := f.Description
			found = &desc
			break
		}
	}
	if found == nil {
		t.Fatal("expected SUPPRESS-REVIEW to fire for bare suppress directive")
	}
	// The new description should mention documenting the reason, not
	// "fix the code instead of suppressing it".
	if !strings.Contains(*found, "reason") {
		t.Errorf("SUPPRESS-REVIEW description should prompt for a reason; got: %s", *found)
	}
}

func TestDetectNewSuppressDirectives_MixedReasonAndBare(t *testing.T) {
	// An edit adding two directives: one with a reason, one without.
	// Only the bare one should trigger SUPPRESS-REVIEW.
	dir := t.TempDir()
	filePath := filepath.Join(dir, "mixed.py")
	original := "def handler():\n    a()\n    b()\n"
	_ = os.WriteFile(filePath, []byte(original), 0644)

	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Edit",
		ToolInput: hook.ToolInput{
			FilePath: filePath,
			OldString: "    a()\n    b()",
			NewString: "    # batou:ignore injection -- validated upstream\n    a()\n    # batou:ignore xss\n    b()",
		},
	}
	result := &reporter.ScanResult{FilePath: filePath}
	newContent := "def handler():\n    # batou:ignore injection -- validated upstream\n    a()\n    # batou:ignore xss\n    b()\n"
	detectNewSuppressDirectives(input, newContent, result)

	reviewCount := 0
	for _, f := range result.Findings {
		if f.RuleID == "BATOU-SUPPRESS-REVIEW" {
			reviewCount++
		}
	}
	if reviewCount != 1 {
		t.Errorf("expected exactly 1 SUPPRESS-REVIEW (for the bare directive); got %d", reviewCount)
	}
}
