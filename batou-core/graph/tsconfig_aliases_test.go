package graph

import (
	"os"
	"path/filepath"
	"testing"
)

// Tests for the dependency-free tsconfig.json alias parser
// (resolver_javascript_tsconfig.go). The string-scanning helpers are pure;
// parseTSConfigAliases / aliasTableForDir read from disk so they use a
// temp project tree.

func TestStripJSONComments(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`{"a":1}`, `{"a":1}`},
		{"{\n// line comment\n\"a\":1}", "{\n\n\"a\":1}"},
		{`{/* block */"a":1}`, `{"a":1}`},
		// Comment markers inside a string are preserved.
		{`{"url":"http://x"}`, `{"url":"http://x"}`},
		{`{"p":"a/*b"}`, `{"p":"a/*b"}`},
	}
	for _, tc := range cases {
		if got := stripJSONComments(tc.in); got != tc.want {
			t.Errorf("stripJSONComments(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExtractJSONStringField(t *testing.T) {
	text := `{ "baseUrl": "./src", "extends": "../base.json", "other": 7 }`
	if got := extractJSONStringField(text, "baseUrl"); got != "./src" {
		t.Errorf("baseUrl = %q, want ./src", got)
	}
	if got := extractJSONStringField(text, "extends"); got != "../base.json" {
		t.Errorf("extends = %q, want ../base.json", got)
	}
	if got := extractJSONStringField(text, "missing"); got != "" {
		t.Errorf("missing field = %q, want empty", got)
	}
}

func TestExtractStringArray(t *testing.T) {
	got := extractStringArray(`"a", "b" , "c"`)
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("extractStringArray len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("extractStringArray[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if got := extractStringArray(""); got != nil {
		t.Errorf("extractStringArray(empty) = %v, want nil", got)
	}
}

func TestExtractPathsObject(t *testing.T) {
	text := `{
		"compilerOptions": {
			"baseUrl": ".",
			"paths": {
				"@services/*": ["services/*"],
				"@util": ["lib/util"]
			}
		}
	}`
	got := extractPathsObject(text)
	if len(got) != 2 {
		t.Fatalf("extractPathsObject got %d keys, want 2: %v", len(got), got)
	}
	if v := got["@services/*"]; len(v) != 1 || v[0] != "services/*" {
		t.Errorf("@services/* = %v, want [services/*]", v)
	}
	if v := got["@util"]; len(v) != 1 || v[0] != "lib/util" {
		t.Errorf("@util = %v, want [lib/util]", v)
	}
	// No paths block -> empty map (not nil).
	if got := extractPathsObject(`{"compilerOptions":{}}`); len(got) != 0 {
		t.Errorf("extractPathsObject(no paths) = %v, want empty", got)
	}
}

func TestCompileAliasRule(t *testing.T) {
	// Wildcard key + wildcard target: prefixes are kept.
	r := compileAliasRule("@services/*", []string{"services/*"})
	if r == nil || !r.hasWildcard || r.keyPrefix != "@services/" {
		t.Fatalf("wildcard rule = %#v", r)
	}
	if len(r.targets) != 1 || r.targets[0] != "services/" {
		t.Errorf("wildcard targets = %v, want [services/]", r.targets)
	}
	// Exact key.
	r = compileAliasRule("@util", []string{"lib/util"})
	if r == nil || r.hasWildcard || r.keyPrefix != "@util" {
		t.Fatalf("exact rule = %#v", r)
	}
	// Empty key/targets -> nil.
	if compileAliasRule("", []string{"x"}) != nil {
		t.Error("empty key should give nil rule")
	}
	if compileAliasRule("k", nil) != nil {
		t.Error("empty targets should give nil rule")
	}
}

func TestResolveAlias(t *testing.T) {
	tbl := &jsAliasTable{
		baseURL: "/proj",
		rules: []jsAliasRule{
			{keyPrefix: "@services/", hasWildcard: true, targets: []string{"src/services/"}},
			{keyPrefix: "@util", hasWildcard: false, targets: []string{"src/lib/util"}},
		},
	}
	// Wildcard match: tail appended to target prefix, joined with baseURL.
	got := tbl.resolveAlias("@services/runner")
	if len(got) != 1 || got[0] != filepath.Join("/proj", "src/services/runner") {
		t.Errorf("resolveAlias(@services/runner) = %v", got)
	}
	// Exact match.
	got = tbl.resolveAlias("@util")
	if len(got) != 1 || got[0] != filepath.Join("/proj", "src/lib/util") {
		t.Errorf("resolveAlias(@util) = %v", got)
	}
	// No declared alias -> nil (npm-scoped imports stay extern).
	if got := tbl.resolveAlias("@nestjs/common"); got != nil {
		t.Errorf("resolveAlias(unmatched) = %v, want nil", got)
	}
	// Nil table / empty specifier -> nil.
	if got := (*jsAliasTable)(nil).resolveAlias("x"); got != nil {
		t.Errorf("nil-table resolveAlias = %v, want nil", got)
	}
	if got := tbl.resolveAlias(""); got != nil {
		t.Errorf("empty-specifier resolveAlias = %v, want nil", got)
	}
}

func TestResolveAlias_LongestPrefixWins(t *testing.T) {
	tbl := &jsAliasTable{
		baseURL: "/proj",
		rules: []jsAliasRule{
			{keyPrefix: "@", hasWildcard: true, targets: []string{"a/"}},
			{keyPrefix: "@svc/", hasWildcard: true, targets: []string{"b/"}},
		},
	}
	got := tbl.resolveAlias("@svc/runner")
	// Most specific rule ("@svc/") wins; tail is "runner".
	if len(got) != 1 || got[0] != filepath.Join("/proj", "b/runner") {
		t.Errorf("resolveAlias longest-prefix = %v, want [/proj/b/runner]", got)
	}
}

func TestParseTSConfigAliases_TempDir(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tsconfig.json")
	content := `{
		// project config
		"compilerOptions": {
			"baseUrl": "./src",
			"paths": {
				"@app/*": ["app/*"]
			}
		}
	}`
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatalf("write tsconfig: %v", err)
	}
	tbl := parseTSConfigAliases(cfg, 0)
	if tbl == nil {
		t.Fatal("parseTSConfigAliases returned nil for a config with paths")
	}
	if tbl.baseURL != filepath.Join(dir, "src") {
		t.Errorf("baseURL = %q, want %q", tbl.baseURL, filepath.Join(dir, "src"))
	}
	got := tbl.resolveAlias("@app/handler")
	if len(got) != 1 || got[0] != filepath.Join(dir, "src", "app", "handler") {
		t.Errorf("resolveAlias via parsed config = %v", got)
	}
}

func TestParseTSConfigAliases_NoPaths(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tsconfig.json")
	if err := os.WriteFile(cfg, []byte(`{"compilerOptions":{"strict":true}}`), 0o600); err != nil {
		t.Fatalf("write tsconfig: %v", err)
	}
	if tbl := parseTSConfigAliases(cfg, 0); tbl != nil {
		t.Errorf("parseTSConfigAliases with no paths = %#v, want nil", tbl)
	}
}

func TestAliasTableForDir_DiscoverAndCache(t *testing.T) {
	root := t.TempDir()
	cfg := filepath.Join(root, "tsconfig.json")
	content := `{"compilerOptions":{"baseUrl":".","paths":{"@x/*":["x/*"]}}}`
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatalf("write tsconfig: %v", err)
	}
	// A nested dir should discover the root tsconfig by walking up.
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	tbl := aliasTableForDir(nested)
	if tbl == nil {
		t.Fatal("aliasTableForDir found no table walking up to root tsconfig")
	}
	if got := tbl.resolveAlias("@x/svc"); len(got) != 1 {
		t.Errorf("resolveAlias through discovered table = %v", got)
	}
	// Empty dir -> nil, no panic.
	if got := aliasTableForDir(""); got != nil {
		t.Errorf("aliasTableForDir(\"\") = %#v, want nil", got)
	}
}
