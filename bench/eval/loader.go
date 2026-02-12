package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadPrompts reads all prompt definition files from a directory.
// Prompts are stored as JSON files (one per prompt or a single array file).
// Supports both a single prompts.json array file and individual {id}.json files.
func LoadPrompts(dir string) ([]Prompt, error) {
	baseDir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return nil, fmt.Errorf("resolving prompts directory: %w", err)
	}

	// Try single array file first
	arrayPath := filepath.Clean(filepath.Join(baseDir, "prompts.json"))
	if !strings.HasPrefix(arrayPath, baseDir) {
		return nil, fmt.Errorf("path escapes base directory")
	}
	data, err := os.ReadFile(arrayPath)
	if err == nil {
		var prompts []Prompt
		if err := json.Unmarshal(data, &prompts); err != nil {
			return nil, fmt.Errorf("parsing prompts.json: %w", err)
		}
		return prompts, nil
	}

	// Fall back to individual files
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, fmt.Errorf("reading prompts directory %s: %w", baseDir, err)
	}

	var prompts []Prompt
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		filePath := filepath.Clean(filepath.Join(baseDir, entry.Name()))
		if !strings.HasPrefix(filePath, baseDir) {
			continue
		}
		fdata, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("reading prompt %s: %w", entry.Name(), err)
		}
		var p Prompt
		if err := json.Unmarshal(fdata, &p); err != nil {
			return nil, fmt.Errorf("parsing prompt %s: %w", entry.Name(), err)
		}
		if p.ID == "" {
			p.ID = strings.TrimSuffix(entry.Name(), ".json")
		}
		prompts = append(prompts, p)
	}
	return prompts, nil
}

// LoadSamples reads generated code samples for a model from the results directory.
// Expected layout: resultsDir/{prompt_id}/{lang}.{ext}
// Also supports a flat layout: resultsDir/{prompt_id}_{lang}.{ext}
// And a single samples.json array file.
func LoadSamples(resultsDir string) ([]GeneratedSample, error) {
	baseDir, err := filepath.Abs(filepath.Clean(resultsDir))
	if err != nil {
		return nil, fmt.Errorf("resolving results directory: %w", err)
	}

	// Try single array file
	arrayPath := filepath.Clean(filepath.Join(baseDir, "samples.json"))
	if !strings.HasPrefix(arrayPath, baseDir) {
		return nil, fmt.Errorf("path escapes base directory")
	}
	data, err := os.ReadFile(arrayPath)
	if err == nil {
		var samples []GeneratedSample
		if err := json.Unmarshal(data, &samples); err != nil {
			return nil, fmt.Errorf("parsing samples.json: %w", err)
		}
		return samples, nil
	}

	// Walk directory entries
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, fmt.Errorf("reading results directory %s: %w", baseDir, err)
	}

	var samples []GeneratedSample
	for _, entry := range entries {
		if !entry.IsDir() {
			// Flat layout: {prompt_id}_{lang}.{ext}
			s, ok := parseFlatSample(baseDir, entry.Name())
			if ok {
				samples = append(samples, s)
			}
			continue
		}

		promptID := entry.Name()
		subDirPath := filepath.Clean(filepath.Join(baseDir, promptID))
		if !strings.HasPrefix(subDirPath, baseDir) {
			continue
		}
		subEntries, err := os.ReadDir(subDirPath)
		if err != nil {
			continue
		}

		for _, se := range subEntries {
			if se.IsDir() || strings.HasPrefix(se.Name(), ".") {
				continue
			}
			lang := langFromExt(filepath.Ext(se.Name()))
			if lang == "" {
				continue
			}
			codePath := filepath.Clean(filepath.Join(subDirPath, se.Name()))
			if !strings.HasPrefix(codePath, baseDir) {
				continue
			}
			code, err := os.ReadFile(codePath)
			if err != nil {
				return nil, fmt.Errorf("reading sample %s/%s: %w", promptID, se.Name(), err)
			}
			samples = append(samples, GeneratedSample{
				PromptID: promptID,
				Language: lang,
				Code:     string(code),
			})
		}
	}

	return samples, nil
}

// LoadSamplesJSON reads samples from a JSON file at a known path.
// The caller must provide the expected base directory for containment validation.
func LoadSamplesJSON(baseDir, relativePath string) ([]GeneratedSample, error) {
	base, err := filepath.Abs(filepath.Clean(baseDir))
	if err != nil {
		return nil, fmt.Errorf("resolving base directory: %w", err)
	}
	resolved := filepath.Clean(filepath.Join(base, relativePath))
	if !strings.HasPrefix(resolved, base) {
		return nil, fmt.Errorf("path %q escapes base directory %q", relativePath, base)
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("reading samples file %s: %w", resolved, err)
	}
	var samples []GeneratedSample
	if err := json.Unmarshal(data, &samples); err != nil {
		return nil, fmt.Errorf("parsing samples file %s: %w", resolved, err)
	}
	return samples, nil
}

// FilterPrompts returns prompts matching the given filters.
// Empty filter values match everything.
func FilterPrompts(prompts []Prompt, owasp, lang, difficulty string) []Prompt {
	var out []Prompt
	for _, p := range prompts {
		if owasp != "" && !strings.EqualFold(p.OWASP, owasp) {
			continue
		}
		if lang != "" && !containsIgnoreCase(p.Languages, lang) {
			continue
		}
		if difficulty != "" && !strings.EqualFold(p.Difficulty, difficulty) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// PromptMap builds a lookup map from prompt ID to Prompt.
func PromptMap(prompts []Prompt) map[string]Prompt {
	m := make(map[string]Prompt, len(prompts))
	for _, p := range prompts {
		m[p.ID] = p
	}
	return m
}

// parseFlatSample tries to parse a flat-layout filename like "sql-injection_python.py".
func parseFlatSample(baseDir, name string) (GeneratedSample, bool) {
	ext := filepath.Ext(name)
	lang := langFromExt(ext)
	if lang == "" {
		return GeneratedSample{}, false
	}

	base := strings.TrimSuffix(name, ext)
	idx := strings.LastIndex(base, "_")
	if idx < 0 {
		return GeneratedSample{}, false
	}

	promptID := base[:idx]
	filePath := filepath.Clean(filepath.Join(baseDir, name))
	if !strings.HasPrefix(filePath, baseDir) {
		return GeneratedSample{}, false
	}
	code, err := os.ReadFile(filePath)
	if err != nil {
		return GeneratedSample{}, false
	}

	return GeneratedSample{
		PromptID: promptID,
		Language: lang,
		Code:     string(code),
	}, true
}

// langFromExt maps a file extension to a language name.
func langFromExt(ext string) string {
	switch strings.ToLower(ext) {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".java":
		return "java"
	case ".rb":
		return "ruby"
	case ".php":
		return "php"
	case ".cs":
		return "csharp"
	case ".c":
		return "c"
	case ".cpp", ".cc", ".cxx":
		return "cpp"
	default:
		return ""
	}
}

// containsIgnoreCase checks if slice contains val (case-insensitive).
func containsIgnoreCase(slice []string, val string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}
