package analyzer

import (
	"path/filepath"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// extToLanguage maps file extensions to Language constants.
var extToLanguage = map[string]rules.Language{
	".go":          rules.LangGo,
	".py":          rules.LangPython,
	".pyw":         rules.LangPython,
	".js":          rules.LangJavaScript,
	".jsx":         rules.LangJavaScript,
	".mjs":         rules.LangJavaScript,
	".cjs":         rules.LangJavaScript,
	".ts":          rules.LangTypeScript,
	".tsx":         rules.LangTypeScript,
	".mts":         rules.LangTypeScript,
	".java":        rules.LangJava,
	".rb":          rules.LangRuby,
	".erb":         rules.LangRuby,
	".php":         rules.LangPHP,
	".cs":          rules.LangCSharp,
	".rs":          rules.LangRust,
	".c":           rules.LangC,
	".h":           rules.LangC,
	".cpp":         rules.LangCPP,
	".cc":          rules.LangCPP,
	".cxx":         rules.LangCPP,
	".c++":         rules.LangCPP,
	".hpp":         rules.LangCPP,
	".hh":          rules.LangCPP,
	".hxx":         rules.LangCPP,
	".h++":         rules.LangCPP,
	".sh":          rules.LangShell,
	".bash":        rules.LangShell,
	".zsh":         rules.LangShell,
	".sql":         rules.LangSQL,
	".yaml":        rules.LangYAML,
	".yml":         rules.LangYAML,
	".json":        rules.LangJSON,
	".tf":          rules.LangTerraform,
	".tfvars":      rules.LangTerraform,
	"Dockerfile":   rules.LangDocker,
	".dockerfile":  rules.LangDocker,
}

// DetectLanguage determines the programming language from a file path.
func DetectLanguage(filePath string) rules.Language {
	base := filepath.Base(filePath)

	// Check full filename first (e.g., "Dockerfile")
	if lang, ok := extToLanguage[base]; ok {
		return lang
	}

	// Check by extension
	ext := strings.ToLower(filepath.Ext(filePath))
	if lang, ok := extToLanguage[ext]; ok {
		return lang
	}

	return rules.LangAny
}

// IsScannable returns true if the file should be scanned.
// Skips binary files, images, fonts, etc.
func IsScannable(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	skipExts := map[string]bool{
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".bmp": true, ".ico": true, ".svg": true, ".webp": true,
		".mp3": true, ".mp4": true, ".wav": true, ".avi": true,
		".zip": true, ".tar": true, ".gz": true, ".bz2": true,
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
		".pdf": true, ".doc": true, ".docx": true,
		".lock": true,
	}

	return !skipExts[ext]
}

// ContentLines splits content into numbered lines for rule scanning.
func ContentLines(content string) []string {
	return strings.Split(content, "\n")
}

// FindLineNumber returns the 1-based line number for a byte offset in content.
func FindLineNumber(content string, offset int) int {
	if offset < 0 || offset >= len(content) {
		return 0
	}
	line := 1
	for i := 0; i < offset && i < len(content); i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}
