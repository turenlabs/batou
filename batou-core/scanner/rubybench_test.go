package scanner_test

import (
	"os"
	"path/filepath"
	"testing"

	_ "github.com/turenlabs/batou-core/taintrule"
)

func TestRubyBench(t *testing.T) {
	root := projectRoot()
	// batou:ignore-start traversal -- test harness paths are built from compile-time project root, not user input
	csvPath := filepath.Join(root, "testdata", "bench", "ruby", "expectedresults.csv")
	testcodeDir := filepath.Join(root, "testdata", "bench", "ruby")
	// batou:ignore-end

	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("Ruby benchmark fixtures not found")
	}

	runOWASPBench(t, "ruby", csvPath, testcodeDir, ".rb")
}
