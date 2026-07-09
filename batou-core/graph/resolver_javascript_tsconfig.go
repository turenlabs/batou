// TypeScript path-alias resolution (PR2 item 1).
//
// ~42% of real-world TypeScript apps declare `compilerOptions.paths`
// (plus `baseUrl`) in tsconfig.json to import sibling modules through
// short aliases — `import {x} from '@services/runner'` instead of a deep
// relative `../../services/runner`. Without parsing tsconfig those
// specifiers look like bare npm packages and the resolver drops them, so
// every cross-file flow through an aliased import is invisible.
//
// This file builds a per-project alias table from tsconfig.json and
// exposes a longest-prefix matcher. resolveJSSpecifier consults it BEFORE
// the bare-specifier early-return, rewriting only specifiers that match a
// DECLARED alias. npm-scoped specifiers (@nestjs/common, @prisma/client)
// that don't match any declared `paths` key fall straight through and
// stay extern — exactly as before.
//
// Parsing is dependency-free (a tiny brace/quote scanner over the JSON,
// matching readPackageJSONName's policy) so the graph package keeps its
// stdlib-only footprint. We support the common `extends` form (a single
// relative parent config) to one level, which covers the dominant
// "tsconfig.base.json" monorepo pattern without unbounded recursion.

package graph

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// jsAliasRule is one compiled `paths` entry. A tsconfig key like
// "@services/*" splits into prefix="@services/" and hasWildcard=true; its
// targets ("services/*") split into prefix="services/". An exact key
// (no `*`) has hasWildcard=false and matches the specifier verbatim.
type jsAliasRule struct {
	keyPrefix   string   // text before `*` in the alias key (or whole key if exact)
	hasWildcard bool     // whether the alias key contained a `*`
	targets     []string // baseUrl-relative replacement templates (text before `*` kept)
}

// jsAliasTable is a project's resolved alias config: an absolute baseUrl
// directory plus the ordered alias rules. A nil/empty table means "no
// aliases" and resolveJSSpecifier behaves exactly as before.
type jsAliasTable struct {
	baseURL string // absolute directory the targets are resolved against
	rules   []jsAliasRule
}

// jsTSConfigCache memoises the alias table discovered for a given start
// directory. Keyed by the directory we began the upward tsconfig walk
// from; the value is the (possibly nil) table. Concurrency-safe because
// ExtractScope may run across files in parallel.
var (
	jsTSConfigCache   = map[string]*jsAliasTable{}
	jsTSConfigCacheMu sync.Mutex
)

// aliasTableForDir returns the alias table governing files under dir,
// walking up to find the nearest tsconfig.json. Results are cached per
// start directory. Returns nil when no tsconfig with usable `paths` is
// found — callers treat nil as "no aliases".
func aliasTableForDir(dir string) *jsAliasTable {
	if dir == "" {
		return nil
	}
	abs := dir
	if !filepath.IsAbs(abs) {
		if a, err := filepath.Abs(abs); err == nil {
			abs = a
		}
	}
	jsTSConfigCacheMu.Lock()
	if t, ok := jsTSConfigCache[abs]; ok {
		jsTSConfigCacheMu.Unlock()
		return t
	}
	jsTSConfigCacheMu.Unlock()

	table := discoverAliasTable(abs)

	jsTSConfigCacheMu.Lock()
	jsTSConfigCache[abs] = table
	jsTSConfigCacheMu.Unlock()
	return table
}

// discoverAliasTable walks up from startDir looking for a tsconfig.json
// that declares compilerOptions.paths. The first tsconfig encountered
// wins (the one whose directory is closest to the file). Returns nil when
// none is found before the filesystem root.
func discoverAliasTable(startDir string) *jsAliasTable {
	cur := startDir
	for {
		candidate := filepath.Join(cur, "tsconfig.json")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			if t := parseTSConfigAliases(candidate, 0); t != nil {
				return t
			}
			// tsconfig present but no usable paths — stop here. A parent
			// tsconfig is unusual and rarely the intended source of paths.
			return nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil
		}
		cur = parent
	}
}

// maxTSConfigExtendsDepth bounds `extends` chasing so a malformed config
// (or a cycle) can't loop forever. One hop covers the dominant
// tsconfig.base.json monorepo pattern.
const maxTSConfigExtendsDepth = 4

// parseTSConfigAliases reads a tsconfig.json and builds its alias table.
// baseUrl defaults to the tsconfig's own directory when unset (TS's own
// default once `paths` is present). When the config `extends` a parent,
// the parent's baseUrl/paths are merged in (child wins) up to a small
// depth bound. Returns nil when no `paths` are declared anywhere in the
// chain.
func parseTSConfigAliases(path string, depth int) *jsAliasTable {
	if depth > maxTSConfigExtendsDepth {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 256*1024 {
		return nil
	}
	dir := filepath.Dir(path)
	text := stripJSONComments(string(data))

	// Resolve `extends` first so the child can override.
	var inherited *jsAliasTable
	if ext := extractJSONStringField(text, "extends"); ext != "" {
		extPath := ext
		if !strings.HasSuffix(extPath, ".json") {
			extPath += ".json"
		}
		if !filepath.IsAbs(extPath) {
			extPath = filepath.Join(dir, extPath)
		}
		inherited = parseTSConfigAliases(extPath, depth+1)
	}

	baseURLRaw := extractJSONStringField(text, "baseUrl")
	pathsBlock := extractPathsObject(text)

	// Nothing local and nothing inherited → no aliases.
	if baseURLRaw == "" && len(pathsBlock) == 0 && inherited == nil {
		return nil
	}

	// Determine effective baseUrl: explicit local > inherited > tsconfig
	// dir (TS default when paths present).
	var baseURL string
	switch {
	case baseURLRaw != "":
		baseURL = filepath.Join(dir, baseURLRaw)
	case inherited != nil && inherited.baseURL != "":
		baseURL = inherited.baseURL
	default:
		baseURL = dir
	}

	rules := make([]jsAliasRule, 0, len(pathsBlock))
	if inherited != nil {
		rules = append(rules, inherited.rules...)
	}
	for key, targets := range pathsBlock {
		rule := compileAliasRule(key, targets)
		if rule != nil {
			rules = append(rules, *rule)
		}
	}
	if len(rules) == 0 {
		return nil
	}
	return &jsAliasTable{baseURL: baseURL, rules: rules}
}

// compileAliasRule turns one `paths` entry ("@services/*": ["services/*"])
// into a jsAliasRule. Returns nil when the key/targets are empty.
func compileAliasRule(key string, targets []string) *jsAliasRule {
	if key == "" || len(targets) == 0 {
		return nil
	}
	r := &jsAliasRule{}
	if star := strings.IndexByte(key, '*'); star >= 0 {
		r.keyPrefix = key[:star]
		r.hasWildcard = true
	} else {
		r.keyPrefix = key
		r.hasWildcard = false
	}
	for _, t := range targets {
		if t == "" {
			continue
		}
		// Keep only the prefix before `*` in the target template; the
		// matched wildcard tail is appended at resolve time.
		if star := strings.IndexByte(t, '*'); star >= 0 {
			r.targets = append(r.targets, t[:star])
		} else {
			r.targets = append(r.targets, t)
		}
	}
	if len(r.targets) == 0 {
		return nil
	}
	return r
}

// resolveAlias longest-prefix-matches specifier against the table and
// returns the candidate baseUrl-relative paths (without extension) to
// try, most-specific rule first. Returns nil when no DECLARED alias
// matches — the caller then leaves the specifier alone (so npm-scoped
// imports stay extern). Each returned path is absolute (joined with
// baseURL).
func (t *jsAliasTable) resolveAlias(specifier string) []string {
	if t == nil || specifier == "" {
		return nil
	}
	var best *jsAliasRule
	var tail string
	for i := range t.rules {
		r := &t.rules[i]
		if r.hasWildcard {
			if !strings.HasPrefix(specifier, r.keyPrefix) {
				continue
			}
			if best == nil || len(r.keyPrefix) > len(best.keyPrefix) {
				best = r
				tail = specifier[len(r.keyPrefix):]
			}
		} else {
			// Exact alias: the specifier must equal the key exactly.
			if specifier != r.keyPrefix {
				continue
			}
			// Exact match is maximally specific.
			best = r
			tail = ""
			break
		}
	}
	if best == nil {
		return nil
	}
	out := make([]string, 0, len(best.targets))
	for _, tgt := range best.targets {
		joined := filepath.Join(t.baseURL, tgt+tail)
		out = append(out, joined)
	}
	return out
}

// stripJSONComments removes // line and /* */ block comments from JSONC
// (tsconfig allows them). It does not honour comment markers inside
// strings perfectly, but tsconfig paths/baseUrl values never contain `//`
// or `/*`, so the heuristic is safe for our field extraction.
func stripJSONComments(s string) string {
	var b strings.Builder
	inStr := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				b.WriteByte(s[i+1])
				i++
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			b.WriteByte(c)
			continue
		}
		if c == '/' && i+1 < len(s) {
			if s[i+1] == '/' {
				for i < len(s) && s[i] != '\n' {
					i++
				}
				if i < len(s) {
					b.WriteByte('\n')
				}
				continue
			}
			if s[i+1] == '*' {
				i += 2
				for i+1 < len(s) && (s[i] != '*' || s[i+1] != '/') {
					i++
				}
				i++ // land on the '/'
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// extractJSONStringField returns the string value of a top-ish-level
// `"field": "value"` pair. Used for "baseUrl" and "extends". It finds the
// first occurrence of the quoted field name followed by a colon and a
// quoted value. Good enough for tsconfig's flat compilerOptions shape;
// not a general JSON parser.
func extractJSONStringField(text, field string) string {
	needle := "\"" + field + "\""
	idx := strings.Index(text, needle)
	if idx < 0 {
		return ""
	}
	rest := text[idx+len(needle):]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return ""
	}
	rest = rest[colon+1:]
	q1 := strings.IndexByte(rest, '"')
	if q1 < 0 {
		return ""
	}
	rest = rest[q1+1:]
	q2 := strings.IndexByte(rest, '"')
	if q2 < 0 {
		return ""
	}
	return rest[:q2]
}

// extractPathsObject parses the `"paths": { ... }` object into a
// key→targets map. Each value is an array of strings. This is a focused
// scanner over the paths block only — it locates the block, then walks
// "key": [ "t1", "t2" ] entries. Returns an empty map when absent.
func extractPathsObject(text string) map[string][]string {
	out := map[string][]string{}
	needle := "\"paths\""
	idx := strings.Index(text, needle)
	if idx < 0 {
		return out
	}
	rest := text[idx+len(needle):]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return out
	}
	rest = rest[colon+1:]
	open := strings.IndexByte(rest, '{')
	if open < 0 {
		return out
	}
	// Find the matching close brace for the paths object.
	depth := 0
	end := -1
	inStr := false
	for i := open; i < len(rest); i++ {
		c := rest[i]
		if inStr {
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return out
	}
	body := rest[open+1 : end]
	// Walk "key": [ ... ] entries.
	for {
		k1 := strings.IndexByte(body, '"')
		if k1 < 0 {
			break
		}
		body = body[k1+1:]
		k2 := strings.IndexByte(body, '"')
		if k2 < 0 {
			break
		}
		key := body[:k2]
		body = body[k2+1:]
		arrOpen := strings.IndexByte(body, '[')
		colon := strings.IndexByte(body, ':')
		if arrOpen < 0 || colon < 0 || colon > arrOpen {
			// Not a "key": [array] pair (malformed) — skip to next quote.
			continue
		}
		arrClose := strings.IndexByte(body, ']')
		if arrClose < 0 {
			break
		}
		arr := body[arrOpen+1 : arrClose]
		body = body[arrClose+1:]
		out[key] = extractStringArray(arr)
	}
	return out
}

// extractStringArray pulls the quoted strings out of a JSON array body
// (the text between [ and ]). Order is preserved.
func extractStringArray(arr string) []string {
	var out []string
	for {
		q1 := strings.IndexByte(arr, '"')
		if q1 < 0 {
			break
		}
		arr = arr[q1+1:]
		q2 := strings.IndexByte(arr, '"')
		if q2 < 0 {
			break
		}
		out = append(out, arr[:q2])
		arr = arr[q2+1:]
	}
	return out
}
