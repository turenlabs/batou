// Regression test for the preprocessed/original line-number split that
// caused suppression directives to silently fail on Python files with
// multi-line paren blocks.
//
// The original failure (Claude Code session 265a06be, 2026-04-22) scanned
// tools/carvera_vacuum.py: a 100-line CLI with a multi-line
// argparse.ArgumentParser(...) and a pathlib read sink further down. A
// `# batou:ignore file_read` comment immediately above the sink did not
// register because:
//
//   - joinPythonContinuations collapsed the argparse block, shifting every
//     subsequent preprocessed line number by N.
//   - suppress.Parse ran on preprocessed content → lineTargets keyed by
//     preprocessed line numbers.
//   - The taint engine parses the ORIGINAL file (ast.Parse uses pre-join
//     content) → flow.SinkLine is an original line number.
//   - filterSuppressedFlows looked up lineTargets[originalSink] → missed.
//
// The fix (ParseWithLineMap + preToOrig) mirrors each preprocessed entry
// across every original line the group spans. This test feeds the scanner
// the exact shape from the session and asserts no BATOU-TAINT finding
// survives suppression.
package scanner_test

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/testutil"

	// Registration imports — copy from layers_test.go to keep taint pipeline live.
	_ "github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	_ "github.com/turenlabs/batou-core/taintrule"
	_ "github.com/turenlabs/batou-rules/rules/traversal"
)

func TestSuppress_PythonMultilineArgparseBelowDirective(t *testing.T) {
	// Shape mirrors tools/carvera_vacuum.py from session 265a06be.
	// The multi-line ArgumentParser spans 4 original lines (a 3-line collapse).
	// Without the fix, the `# batou:ignore file_read` comment on line 11 would
	// fail to suppress the taint flow at line 12 because the two lived in
	// different line-coordinate systems.
	code := `import argparse
from pathlib import Path

parser = argparse.ArgumentParser(
    description="add vacuum M-codes to a carvera nc file",
    prog="carvera_vacuum",
)
parser.add_argument("input", type=Path)
args = parser.parse_args()

# batou:ignore file_read -- local CLI utility; user-supplied path is intentional
lines = args.input.read_text().splitlines(keepends=True)
print(lines)
`

	result := testutil.ScanContent(t, "/app/carvera_vacuum.py", code)

	for _, f := range result.Findings {
		if strings.HasPrefix(f.RuleID, "BATOU-TAINT-file_read") {
			t.Errorf("taint finding %s at line %d should have been suppressed by the directive on line 11",
				f.RuleID, f.LineNumber)
		}
	}

	// Scan must not block — the suppression should have landed.
	if result.Blocked {
		t.Errorf("scan should not block; got findings: %v", testutil.FindingRuleIDs(result))
	}
}

func TestSuppress_PythonMultilineArgparseBlockDirective(t *testing.T) {
	// The block-suppression form also has to work across the collapse.
	code := `import argparse
from pathlib import Path

parser = argparse.ArgumentParser(
    description="demo",
)
parser.add_argument("input", type=Path)
args = parser.parse_args()

# batou:ignore-start file_read
lines = args.input.read_text().splitlines(keepends=True)
# batou:ignore-end
print(lines)
`

	result := testutil.ScanContent(t, "/app/cli.py", code)

	for _, f := range result.Findings {
		if strings.HasPrefix(f.RuleID, "BATOU-TAINT-file_read") {
			t.Errorf("block-scoped directive should suppress %s at line %d", f.RuleID, f.LineNumber)
		}
	}
}

func TestSuppress_PythonWithoutCollapseStillWorks(t *testing.T) {
	// Guardrail: the fix must not regress the simple case. A flat file with
	// no joining should suppress exactly as before.
	code := `from pathlib import Path
import sys

# batou:ignore file_read -- intentional
data = Path(sys.argv[1]).read_text()
print(data)
`

	result := testutil.ScanContent(t, "/app/flat.py", code)

	for _, f := range result.Findings {
		if strings.HasPrefix(f.RuleID, "BATOU-TAINT-file_read") {
			t.Errorf("flat-file directive should still suppress %s at line %d", f.RuleID, f.LineNumber)
		}
	}
}
