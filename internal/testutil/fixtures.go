package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// FixtureDir returns the absolute path to the testdata/fixtures/ directory.
// It works by locating the project root relative to this source file.
func FixtureDir() string {
	// Use runtime.Caller to find this file's location, then navigate to
	// the project root's testdata/fixtures directory.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		// Fallback: try relative to cwd
		abs, err := filepath.Abs("testdata/fixtures")
		if err != nil {
			return "testdata/fixtures"
		}
		return abs
	}
	// thisFile is .../internal/testutil/fixtures.go
	// project root is two directories up from internal/testutil/
	dir := filepath.Dir(thisFile)                       // internal/testutil
	projectRoot := filepath.Dir(filepath.Dir(dir))       // project root
	return filepath.Join(projectRoot, "testdata", "fixtures")
}

// LoadFixture reads a fixture file and returns its content as a string.
// The relativePath is relative to testdata/fixtures/.
// Fails the test if the file cannot be read.
func LoadFixture(t *testing.T, relativePath string) string {
	t.Helper()

	fullPath := filepath.Join(FixtureDir(), relativePath)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("failed to load fixture %q: %v", relativePath, err)
	}
	return string(data)
}

// VulnerableFixtures returns a map of fixture name to content for all
// vulnerable fixture files for the given language.
// Language should be the directory name, e.g., "go", "python", "javascript".
// Files are loaded from testdata/fixtures/<lang>/vulnerable/.
func VulnerableFixtures(t *testing.T, lang string) map[string]string {
	t.Helper()
	return loadFixtureDir(t, filepath.Join(lang, "vulnerable"))
}

// SafeFixtures returns a map of fixture name to content for all safe
// fixture files for the given language.
// Language should be the directory name, e.g., "go", "python", "javascript".
// Files are loaded from testdata/fixtures/<lang>/safe/.
func SafeFixtures(t *testing.T, lang string) map[string]string {
	t.Helper()
	return loadFixtureDir(t, filepath.Join(lang, "safe"))
}

// loadFixtureDir reads all files in a fixture subdirectory and returns
// them as name -> content. Returns an empty map if the directory doesn't exist.
func loadFixtureDir(t *testing.T, relDir string) map[string]string {
	t.Helper()

	dir := filepath.Join(FixtureDir(), relDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}
		}
		t.Fatalf("failed to read fixture directory %q: %v", relDir, err)
	}

	result := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip hidden files and non-source files
		if strings.HasPrefix(name, ".") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("failed to read fixture %q: %v", filepath.Join(relDir, name), err)
		}
		result[name] = string(data)
	}
	return result
}

// FixturePath returns the absolute path to a fixture file at
// testdata/fixtures/{lang}/{name}. This does not check if the file exists.
func FixturePath(lang, name string) string {
	return filepath.Join(FixtureDir(), lang, name)
}

// VulnerableFixtureNames returns the file names of all vulnerable fixtures
// for the given language directory (e.g., "go", "javascript", "python").
// Returns nil if the directory doesn't exist.
func VulnerableFixtureNames(lang string) []string {
	return listFixtureNames(filepath.Join(lang, "vulnerable"))
}

// SafeFixtureNames returns the file names of all safe fixtures
// for the given language directory.
// Returns nil if the directory doesn't exist.
func SafeFixtureNames(lang string) []string {
	return listFixtureNames(filepath.Join(lang, "safe"))
}

// listFixtureNames returns file names in a fixture subdirectory,
// skipping directories and hidden files.
func listFixtureNames(relDir string) []string {
	dir := filepath.Join(FixtureDir(), relDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		names = append(names, entry.Name())
	}
	return names
}

// FixtureExists returns true if a fixture file exists at the given relative path.
func FixtureExists(relativePath string) bool {
	fullPath := filepath.Join(FixtureDir(), relativePath)
	_, err := os.Stat(fullPath)
	return err == nil
}

// LangExtension maps language directory names to typical file extensions
// for constructing filePaths that trigger correct language detection.
var LangExtension = map[string]string{
	"go":         ".go",
	"py":         ".py",
	"js":         ".js",
	"ts":         ".ts",
	"java":       ".java",
	"rb":         ".rb",
	"php":        ".php",
	"c":          ".c",
	"cpp":        ".cpp",
	"cs":         ".cs",
	"rs":         ".rs",
	"sh":         ".sh",
	"sql":        ".sql",
	"yaml":       ".yaml",
	"json":       ".json",
	"dockerfile": ".dockerfile",
	"tf":         ".tf",
}

// BenchFixture holds a single benchmark fixture with its file metadata.
type BenchFixture struct {
	Lang     string // Language directory name (e.g., "javascript", "python")
	FileName string // Base file name (e.g., "a03_sql_injection.py")
	Content  string // Full file content
	FullPath string // Absolute path to the fixture file
}

// BenchFixtures discovers and loads all vulnerable fixtures under
// testdata/fixtures/bench/{lang}/vulnerable/. Returns nil if the bench
// directory does not exist.
func BenchFixtures(t *testing.T) []BenchFixture {
	t.Helper()

	benchDir := filepath.Join(FixtureDir(), "bench")
	langEntries, err := os.ReadDir(benchDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("failed to read bench directory: %v", err)
	}

	var fixtures []BenchFixture
	for _, langEntry := range langEntries {
		if !langEntry.IsDir() {
			continue
		}
		lang := langEntry.Name()
		vulnDir := filepath.Join(benchDir, lang, "vulnerable")
		fileEntries, err := os.ReadDir(vulnDir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("failed to read %s: %v", vulnDir, err)
		}

		for _, fe := range fileEntries {
			if fe.IsDir() || strings.HasPrefix(fe.Name(), ".") {
				continue
			}
			fp := filepath.Join(vulnDir, fe.Name())
			data, err := os.ReadFile(fp)
			if err != nil {
				t.Fatalf("failed to read bench fixture %s: %v", fp, err)
			}
			fixtures = append(fixtures, BenchFixture{
				Lang:     lang,
				FileName: fe.Name(),
				Content:  string(data),
				FullPath: fp,
			})
		}
	}
	return fixtures
}

// BenchSafeFixtures discovers and loads all safe fixtures under
// testdata/fixtures/bench/{lang}/safe/. Returns nil if the bench
// directory does not exist.
func BenchSafeFixtures(t *testing.T) []BenchFixture {
	t.Helper()

	benchDir := filepath.Join(FixtureDir(), "bench")
	langEntries, err := os.ReadDir(benchDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("failed to read bench directory: %v", err)
	}

	var fixtures []BenchFixture
	for _, langEntry := range langEntries {
		if !langEntry.IsDir() {
			continue
		}
		lang := langEntry.Name()
		safeDir := filepath.Join(benchDir, lang, "safe")
		fileEntries, err := os.ReadDir(safeDir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("failed to read %s: %v", safeDir, err)
		}

		for _, fe := range fileEntries {
			if fe.IsDir() || strings.HasPrefix(fe.Name(), ".") {
				continue
			}
			fp := filepath.Join(safeDir, fe.Name())
			data, err := os.ReadFile(fp)
			if err != nil {
				t.Fatalf("failed to read bench safe fixture %s: %v", fp, err)
			}
			fixtures = append(fixtures, BenchFixture{
				Lang:     lang,
				FileName: fe.Name(),
				Content:  string(data),
				FullPath: fp,
			})
		}
	}
	return fixtures
}

// BenchDirExists returns true if the bench fixtures directory exists.
func BenchDirExists() bool {
	benchDir := filepath.Join(FixtureDir(), "bench")
	_, err := os.Stat(benchDir)
	return err == nil
}
