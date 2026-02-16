package analyzer_test

import (
	"testing"

	"github.com/turenlabs/batou/internal/analyzer"
	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// DetectLanguage — all supported extensions
// ---------------------------------------------------------------------------

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		path string
		want rules.Language
	}{
		// Go
		{"app/main.go", rules.LangGo},

		// Python
		{"app/handler.py", rules.LangPython},
		{"app/gui.pyw", rules.LangPython},

		// JavaScript
		{"app/index.js", rules.LangJavaScript},
		{"app/component.jsx", rules.LangJavaScript},
		{"app/lib.mjs", rules.LangJavaScript},
		{"app/lib.cjs", rules.LangJavaScript},

		// TypeScript
		{"app/index.ts", rules.LangTypeScript},
		{"app/component.tsx", rules.LangTypeScript},
		{"app/lib.mts", rules.LangTypeScript},

		// Java
		{"app/Main.java", rules.LangJava},

		// Ruby
		{"app/handler.rb", rules.LangRuby},
		{"app/view.erb", rules.LangRuby},

		// PHP
		{"app/index.php", rules.LangPHP},

		// C#
		{"app/Program.cs", rules.LangCSharp},

		// Rust
		{"app/main.rs", rules.LangRust},

		// C
		{"app/main.c", rules.LangC},
		{"app/header.h", rules.LangC},

		// C++
		{"app/main.cpp", rules.LangCPP},
		{"app/main.cc", rules.LangCPP},
		{"app/main.cxx", rules.LangCPP},
		{"app/main.c++", rules.LangCPP},
		{"app/header.hpp", rules.LangCPP},
		{"app/header.hh", rules.LangCPP},
		{"app/header.hxx", rules.LangCPP},
		{"app/header.h++", rules.LangCPP},

		// Shell
		{"app/deploy.sh", rules.LangShell},
		{"app/setup.bash", rules.LangShell},
		{"app/init.zsh", rules.LangShell},

		// SQL
		{"app/schema.sql", rules.LangSQL},

		// YAML
		{"app/config.yaml", rules.LangYAML},
		{"app/config.yml", rules.LangYAML},

		// JSON
		{"app/package.json", rules.LangJSON},

		// Terraform
		{"app/main.tf", rules.LangTerraform},
		{"app/vars.tfvars", rules.LangTerraform},

		// Docker
		{"Dockerfile", rules.LangDocker},
		{"app/build.dockerfile", rules.LangDocker},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := analyzer.DetectLanguage(tt.path)
			if got != tt.want {
				t.Errorf("DetectLanguage(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestDetectLanguageUnknownExtension(t *testing.T) {
	got := analyzer.DetectLanguage("app/readme.md")
	if got != rules.LangAny {
		t.Errorf("DetectLanguage for unknown extension = %q, want %q", got, rules.LangAny)
	}
}

func TestDetectLanguageNoExtension(t *testing.T) {
	got := analyzer.DetectLanguage("Makefile")
	if got != rules.LangAny {
		t.Errorf("DetectLanguage for no extension = %q, want %q", got, rules.LangAny)
	}
}

func TestDetectLanguageCaseInsensitiveExtension(t *testing.T) {
	// Extensions are lowercased before lookup.
	got := analyzer.DetectLanguage("app/main.GO")
	if got != rules.LangGo {
		t.Errorf("DetectLanguage with uppercase ext = %q, want %q", got, rules.LangGo)
	}
}

// ---------------------------------------------------------------------------
// IsScannable
// ---------------------------------------------------------------------------

func TestIsScannableForCodeFiles(t *testing.T) {
	codeFiles := []string{
		"main.go", "index.js", "handler.py", "App.java",
		"main.rs", "lib.rb", "index.php", "main.c",
	}
	for _, f := range codeFiles {
		if !analyzer.IsScannable(f) {
			t.Errorf("IsScannable(%q) = false, want true", f)
		}
	}
}

func TestIsScannableSkipsBinaryAndMedia(t *testing.T) {
	skipFiles := []string{
		"image.png", "photo.jpg", "photo.jpeg", "anim.gif",
		"icon.bmp", "favicon.ico", "logo.svg", "image.webp",
		"song.mp3", "video.mp4", "audio.wav", "clip.avi",
		"archive.zip", "archive.tar", "archive.gz", "archive.bz2",
		"app.exe", "lib.dll", "lib.so", "lib.dylib",
		"font.woff", "font.woff2", "font.ttf", "font.eot",
		"doc.pdf", "doc.doc", "doc.docx",
		"yarn.lock",
	}
	for _, f := range skipFiles {
		if analyzer.IsScannable(f) {
			t.Errorf("IsScannable(%q) = true, want false", f)
		}
	}
}

func TestIsScannableCaseInsensitive(t *testing.T) {
	if analyzer.IsScannable("IMAGE.PNG") {
		t.Error("IsScannable should be case-insensitive for skip extensions")
	}
}

// ---------------------------------------------------------------------------
// ContentLines
// ---------------------------------------------------------------------------

func TestContentLines(t *testing.T) {
	lines := analyzer.ContentLines("line1\nline2\nline3")
	if len(lines) != 3 {
		t.Errorf("ContentLines returned %d lines, want 3", len(lines))
	}
	if lines[0] != "line1" || lines[2] != "line3" {
		t.Errorf("ContentLines unexpected content: %v", lines)
	}
}

func TestContentLinesEmpty(t *testing.T) {
	lines := analyzer.ContentLines("")
	if len(lines) != 1 {
		t.Errorf("ContentLines on empty string = %d lines, want 1 (empty string split)", len(lines))
	}
}

// ---------------------------------------------------------------------------
// FindLineNumber
// ---------------------------------------------------------------------------

func TestFindLineNumber(t *testing.T) {
	content := "aaa\nbbb\nccc"
	tests := []struct {
		offset int
		want   int
	}{
		{0, 1},  // first char of line 1
		{2, 1},  // last char of line 1
		{4, 2},  // first char of line 2
		{8, 3},  // first char of line 3
		{-1, 0}, // negative offset
	}

	for _, tt := range tests {
		got := analyzer.FindLineNumber(content, tt.offset)
		if got != tt.want {
			t.Errorf("FindLineNumber(content, %d) = %d, want %d", tt.offset, got, tt.want)
		}
	}
}

func TestFindLineNumberOutOfBounds(t *testing.T) {
	got := analyzer.FindLineNumber("abc", 100)
	if got != 0 {
		t.Errorf("FindLineNumber with offset out of bounds = %d, want 0", got)
	}
}
