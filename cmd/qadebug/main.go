package main

import (
	"fmt"
	"os"

	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
	_ "github.com/turenlabs/batou/internal/taint/languages"
)

func main() {
	files := []string{
		"/tmp/juice-shop/routes/redirect.ts",
		"/tmp/juice-shop/routes/showProductReviews.ts",
		"/tmp/juice-shop/routes/updateProductReviews.ts",
	}

	for _, fname := range files {
		c, err := os.ReadFile(fname)
		if err != nil {
			fmt.Printf("ERROR: %s: %v\n", fname, err)
			continue
		}
		fmt.Printf("=== %s ===\n", fname)
		content := string(c)

		scopes := taint.DetectScopes(content, rules.LangTypeScript)
		fmt.Printf("  Scopes: %d\n", len(scopes))
		for _, s := range scopes {
			if s.Name != "__top_level__" {
				fmt.Printf("    %q lines %d-%d params=%v\n", s.Name, s.StartLine, s.EndLine, s.Params)
			}
		}

		flows := taint.Analyze(content, fname, rules.LangTypeScript)
		fmt.Printf("  Taint flows: %d\n", len(flows))
		for i, f := range flows {
			fmt.Printf("    Flow %d: %s -> %s (confidence=%.2f) L%d->L%d\n", i, f.Source.ID, f.Sink.ID, f.Confidence, f.SourceLine, f.SinkLine)
		}
		fmt.Println()
	}
}
