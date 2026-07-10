package scanner_test

import (
	"os"
	"path/filepath"
	"testing"
	_ "github.com/turenlabs/batou-core/taintrule"
)

func TestKotlinBench(t *testing.T) {
	root := projectRoot()
	csvPath := filepath.Join(root, "testdata", "bench", "kotlin", "expectedresults.csv")
	testcodeDir := filepath.Join(root, "testdata", "bench", "kotlin")

	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Skip("Kotlin benchmark fixtures not found")
	}

	runOWASPBench(t, "kotlin", csvPath, testcodeDir, ".kt")
}
