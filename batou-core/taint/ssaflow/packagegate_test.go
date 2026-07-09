package ssaflow

import "testing"

// TestMethodNamePackageMatches locks the package-gate fix for the deser
// sink-mislabel bug. Before the fix, packageCallMatches routed the catalog
// MethodName through methodComponents(), which strips the package qualifier —
// so "xml.NewDecoder" collapsed to bare "NewDecoder" and matched ANY package's
// NewDecoder (json.NewDecoder rendered as xml.NewDecoder / CWE-611, errors.New
// as md5.New, http.Client.Do as fasthttp.Do). The pure helper below must verify
// the qualifier when the catalog entry carries one, while still allowing
// bare-name catalog entries to match any package.
func TestMethodNamePackageMatches(t *testing.T) {
	cases := []struct {
		name        string
		calleeShort string
		calleePkg   string
		methodName  string
		want        bool
	}{
		// The mislabel that started this: json.NewDecoder must NOT match the
		// xml.NewDecoder catalog entry.
		{"json_not_xml", "NewDecoder", "json", "xml.NewDecoder", false},
		{"yaml_not_xml", "NewDecoder", "yaml", "xml.NewDecoder", false},
		{"gob_not_xml", "NewDecoder", "gob", "xml.NewDecoder", false},
		// Correctly-qualified matches still fire.
		{"xml_matches_xml", "NewDecoder", "xml", "xml.NewDecoder", true},
		{"yaml_matches_yaml", "NewDecoder", "yaml", "yaml.NewDecoder", true},
		{"gob_matches_gob", "NewDecoder", "gob", "gob.NewDecoder", true},
		// Other mislabels the bug produced.
		{"errors_new_not_md5", "New", "errors", "md5.New", false},
		{"md5_new_matches", "New", "crypto/md5", "md5.New", false}, // pkg name is "md5" not "crypto/md5"
		{"md5_new_matches_short", "New", "md5", "md5.New", true},
		// Bare-name catalog entry matches any package.
		{"bare_matches_any", "Command", "exec", "Command", true},
		{"bare_matches_other", "Command", "somepkg", "Command", true},
		// Compound ("/"-separated) catalog method names: each component keeps
		// its own qualifier and is checked independently.
		{"compound_first", "Query", "sql", "sql.Query/sql.Exec", true},
		{"compound_wrong_pkg", "Query", "gorm", "sql.Query/sql.Exec", false},
		{"compound_bare_component", "Exec", "anypkg", "sql.Query/Exec", true},
		// Short-name mismatch never matches regardless of package.
		{"short_mismatch", "Decode", "xml", "xml.NewDecoder", false},
		// Empty callee package can't satisfy a qualified entry.
		{"empty_pkg_qualified", "NewDecoder", "", "xml.NewDecoder", false},
		{"empty_pkg_bare", "NewDecoder", "", "NewDecoder", true},

		// Receiver-blind sink fix (grafana smoke test): the path-Join sink is
		// now qualified "filepath.Join/path.Join", so error/string aggregation
		// no longer mislabels as a path-traversal file-write sink.
		{"errors_join_not_path", "Join", "errors", "filepath.Join/path.Join", false},
		{"strings_join_not_path", "Join", "strings", "filepath.Join/path.Join", false},
		{"filepath_join_matches", "Join", "filepath", "filepath.Join/path.Join", true},
		{"path_join_matches", "Join", "path", "filepath.Join/path.Join", true},
		// The http.Get SSRF sink is now qualified "http.Get", so an in-memory
		// cache.Get(key) no longer mislabels as url_fetch/SSRF.
		{"cache_get_not_http", "Get", "cache", "http.Get", false},
		{"bigcache_get_not_http", "Get", "bigcache", "http.Get", false},
		{"http_get_matches", "Get", "http", "http.Get", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := methodNamePackageMatches(tc.calleeShort, tc.calleePkg, tc.methodName)
			if got != tc.want {
				t.Errorf("methodNamePackageMatches(%q, %q, %q) = %v, want %v",
					tc.calleeShort, tc.calleePkg, tc.methodName, got, tc.want)
			}
		})
	}
}
