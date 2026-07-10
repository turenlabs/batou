package scanner_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/turenlabs/batou-core/testutil"
)

func TestDiscourseTaintDetail(t *testing.T) {
	root := projectRoot()
	repoDir := filepath.Join(root, "testdata", "external", "discourse")
	if _, err := os.Stat(repoDir); os.IsNotExist(err) {
		t.Skip("Discourse not cloned")
	}

	maxP := runtime.GOMAXPROCS(0)
	if maxP < 2 { maxP = 2 }
	sem := make(chan struct{}, maxP)
	var mu sync.Mutex
	benchDir := t.TempDir()

	type taintHit struct {
		File string
		Line int
		Rule string
		Text string
	}
	var hits []taintHit

	var files []string
	_ = filepath.Walk(repoDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() { return nil }
		if info.IsDir() && (info.Name() == "vendor" || info.Name() == ".git" || info.Name() == "node_modules" || info.Name() == "spec" || info.Name() == "test") {
			return filepath.SkipDir
		}
		if strings.HasSuffix(p, ".rb") { files = append(files, p) }
		return nil
	})

	var wg sync.WaitGroup
	for _, p := range files {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer func() { _ = recover() }()

			content, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(repoDir, p)
			res := testutil.ScanContentInDir(t, "/app/discourse/"+rel, string(content), benchDir)
			for _, f := range res.Findings {
				if strings.HasPrefix(f.RuleID, "BATOU-TAINT") {
					mu.Lock()
					hits = append(hits, taintHit{rel, f.LineNumber, f.RuleID, f.MatchedText})
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	// Group by rule
	grouped := make(map[string][]taintHit)
	for _, h := range hits {
		grouped[h.Rule] = append(grouped[h.Rule], h)
	}
	for rule, hh := range grouped {
		fmt.Fprintf(os.Stderr, "\n=== %s (%d) ===\n", rule, len(hh))
		for _, h := range hh {
			text := h.Text
			if len(text) > 100 { text = text[:100] }
			text = strings.ReplaceAll(text, "\n", " ")
			fmt.Fprintf(os.Stderr, "  %s:%d  %s\n", h.File, h.Line, text)
		}
	}
}
