package scanner

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// jsFilterAllFindings applies JavaScript/TypeScript-specific false-positive
// suppression to ALL findings (regex + taint + AST). This runs at the scanner
// level after dedup, so it can suppress regex rule findings that the taint-level
// filter in taintrule/rule.go cannot reach.
//
// The approach: for each finding, check if the surrounding code contains a
// safety pattern (safe API, sanitizer, guard, type coercion) that neutralizes
// the specific CWE. If so, suppress the finding entirely.
func jsFilterAllFindings(content string, findings []rules.Finding) []rules.Finding {
	lines := strings.Split(content, "\n")
	kept := make([]rules.Finding, 0, len(findings))

	// File-level context: a browser-side JS/TS file (Vite/React/Vue/Svelte/
	// Next-client/etc.) cannot have classic Server-Side Request Forgery —
	// the browser IS the user agent, not a server tricked into talking to
	// attacker-chosen hosts. CWE-918 only fits a server-side fetch sink.
	isBrowser := isBrowserSideJSFile(content)

	for _, f := range findings {
		lineIdx := f.LineNumber - 1
		if lineIdx < 0 || lineIdx >= len(lines) {
			kept = append(kept, f)
			continue
		}

		cwe := strings.TrimPrefix(f.CWEID, "CWE-")

		suppressed := false
		switch cwe {
		case "89": // SQL Injection
			suppressed = jsScanHasSQLGuard(lines, lineIdx)
		case "79": // XSS
			suppressed = jsScanHasXSSGuard(lines, lineIdx)
		case "78": // Command Injection
			suppressed = jsScanHasCmdiGuard(lines, lineIdx)
		case "22": // Path Traversal
			suppressed = jsScanHasPathGuard(lines, lineIdx)
		case "918": // SSRF
			// Browser-side fetch cannot SSRF: there's no server to trick.
			// Same applies to relative URL literals (`fetch('/api/x')`)
			// even outside browser context — those are pinned to the
			// process's own origin / working directory.
			if isBrowser || jsFetchArgIsRelativeLiteral(lines[lineIdx]) {
				suppressed = true
			} else {
				suppressed = jsScanHasSSRFGuard(lines, lineIdx)
			}
		case "943": // NoSQL Injection
			suppressed = jsScanHasNoSQLGuard(lines, lineIdx, f.RuleID)
		case "502": // Deserialization
			suppressed = jsScanHasDeserGuard(lines, lineIdx)
		case "1336": // SSTI
			suppressed = jsScanHasSSTIGuard(lines, lineIdx)
		case "601": // Open Redirect
			suppressed = jsScanHasRedirectGuard(lines, lineIdx)
		}

		if suppressed {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// isBrowserSideJSFile returns true when the file's content shows clear
// browser/bundler signals: Vite env (`import.meta.env`), React/Vue/Svelte
// imports, JSX elements, browser globals (`window.`, `document.`),
// Next.js client directive, or webpack `process.env.NEXT_PUBLIC_`.
// SSRF (CWE-918) is a server-side class and does not apply to browser
// code, where `fetch()` runs in the user's browser against their own
// origin (the user cannot be made to attack a private network they
// don't already have access to via an SSRF chain).
var (
	reJSViteEnv         = regexp.MustCompile(`import\.meta\.env\b`)
	reJSImportMetaURL   = regexp.MustCompile(`import\.meta\.url\b`)
	reJSReactImport     = regexp.MustCompile(`(?m)^\s*import\b[^;\n]*\bfrom\s+['"](?:react|react-dom|vue|svelte|solid-js|preact|@angular/[^'"]+|next/[^'"]+|nuxt[^'"]*|astro[^'"]*|qwik[^'"]*|lit|lit-element|lit-html|@lit-labs/[^'"]+)['"]`)
	reJSUseClientDir    = regexp.MustCompile(`^\s*(?:'use client'|"use client")`)
	reJSWindowGlobal    = regexp.MustCompile(`\bwindow\.(?:location|document|history|navigator|localStorage|sessionStorage|fetch|alert|confirm)\b`)
	reJSDocumentGlobal  = regexp.MustCompile(`\bdocument\.(?:getElementById|querySelector|querySelectorAll|createElement|body\b|head\b|cookie\b|location\b|title\b)\b`)
	reJSNextPublicEnv   = regexp.MustCompile(`process\.env\.NEXT_PUBLIC_`)
	reJSJSXReturn       = regexp.MustCompile(`(?m)^\s*return\s*\(\s*<[A-Za-z]`)
	reJSReactCreate     = regexp.MustCompile(`React\.createElement\s*\(|ReactDOM\.(?:render|createRoot)\s*\(`)
	reJSVueDefine       = regexp.MustCompile(`\bdefineComponent\s*\(|createApp\s*\(`)
	reJSExportDefaultFC = regexp.MustCompile(`(?m)^\s*export\s+default\s+function\s+[A-Z]\w*\s*\(\s*\{\s*\w`)
)

func isBrowserSideJSFile(content string) bool {
	// First scan a bounded prefix for cheap signals (most browser files
	// show import statements / "use client" in the first ~4KB).
	head := content
	if len(head) > 8192 {
		head = head[:8192]
	}
	if reJSViteEnv.MatchString(head) ||
		reJSImportMetaURL.MatchString(head) ||
		reJSReactImport.MatchString(head) ||
		reJSUseClientDir.MatchString(head) ||
		reJSNextPublicEnv.MatchString(head) ||
		reJSReactCreate.MatchString(head) ||
		reJSVueDefine.MatchString(head) ||
		reJSExportDefaultFC.MatchString(head) {
		return true
	}
	// Browser globals can appear anywhere; full scan as fallback.
	return reJSWindowGlobal.MatchString(content) ||
		reJSDocumentGlobal.MatchString(content) ||
		reJSJSXReturn.MatchString(content)
}

// jsFetchArgIsRelativeLiteral returns true when the line's fetch/request
// call passes a string literal that starts with '/' (relative path) — a
// pattern used by browser frontends and tests calling their own backend
// over the dev proxy / same-origin path. These cannot be SSRF because
// the URL is fixed at the source.
// Match `/api/...` but NOT `//attacker/...` (protocol-relative URLs are a
// real security risk because they inherit the page's scheme).
var reJSFetchRelativeLit = regexp.MustCompile(`\b(?:fetch|request|axios(?:\.[a-z]+)?|got(?:\.[a-z]+)?|http\.get|https\.get)\s*\(\s*(?:['"]/[^/'"\s][^'"]*['"]|\x60/[^/\x60][^\x60]*\x60)`)

func jsFetchArgIsRelativeLiteral(line string) bool {
	return reJSFetchRelativeLit.MatchString(line)
}

// --- Regex patterns for scanner-level JS FP filtering ---

// SQL safety patterns
var jsScParamQuery = regexp.MustCompile(`\?\s*['"]?\s*,\s*\[`)
var jsScKnexBuilder = regexp.MustCompile(`knex\s*\(\s*['"]`)
var jsScKnexRawSafe = regexp.MustCompile(`knex\.raw\s*\([^,]*\?\s*['"]?\s*,\s*\[`)
var jsScSequelize = regexp.MustCompile(`replacements|bind\s*:`)
var jsScPrisma = regexp.MustCompile("Prisma\\.sql\\s*`")

// XSS safety patterns
var jsScHTMLSanitizer = regexp.MustCompile(`\b(?:escapeHtml|DOMPurify\.sanitize|validator\.escape|sanitizeHtml|he\.encode|he\.escape|encodeURIComponent|xss)\s*\(`)
var jsScResJSON = regexp.MustCompile(`res\.json\s*\(`)
var jsScJSONStringify = regexp.MustCompile(`JSON\.stringify\s*\(`)
var jsScContentType = regexp.MustCompile(`['"]application/json['"]`)

// Command injection safety patterns
var jsScExecFile = regexp.MustCompile(`\bexecFile\s*\(`)
var jsScSpawnSafe = regexp.MustCompile(`\bspawn\s*\(`)
var jsScShellTrue = regexp.MustCompile(`shell\s*:\s*true`)
var jsScDNS = regexp.MustCompile(`dns\.(?:lookup|resolve)\s*\(`)
var jsScFsAPI = regexp.MustCompile(`fs\.(?:appendFile|writeFile|readFile)\s*\(`)

// Path traversal safety patterns
var jsScPathBasename = regexp.MustCompile(`path\.basename\s*\(`)
var jsScPathResolve = regexp.MustCompile(`path\.(?:resolve|normalize)\s*\(`)
var jsScStartsWith = regexp.MustCompile(`\.startsWith\s*\(`)
var jsScSendFileRoot = regexp.MustCompile(`\.sendFile\s*\([^)]*\{\s*root\s*:`)

// SSRF safety patterns
var jsScNewURL = regexp.MustCompile(`new\s+URL\s*\(`)
var jsScHostname = regexp.MustCompile(`\.(?:hostname|origin|protocol)\b`)
var jsScValidatorIsURL = regexp.MustCompile(`validator\.isURL\s*\(`)

// NoSQL safety patterns
var jsScMongoSanitize = regexp.MustCompile(`mongo-sanitize|express-mongo-sanitize`)
var jsScEqOperator = regexp.MustCompile(`\$eq\s*:`)

// Type coercion and allowlist patterns
var jsScTypeCoerce = regexp.MustCompile(`\b(?:parseInt|parseFloat|Number|String)\s*\(|new\s+Date\s*\(`)
var jsScAllowlist = regexp.MustCompile(`(?i)(?:ALLOWED|VALID|whitelist|SAFE)\w*\.(?:includes|has)\s*\(`)
var jsScMapLookup = regexp.MustCompile(`[A-Z_]{2,}\[\w+\]`)
var jsScRegexGuard = regexp.MustCompile(`/\^[^/]+\$/|\.test\s*\(\s*\w+\s*\)`)
var jsScSchemaValid = regexp.MustCompile(`(?:schema|Schema)\.(?:parse|safeParse|validate)\s*\(|ajv\.validate|Joi\.validate`)

// Redirect safety patterns
var jsScRelativeGuard = regexp.MustCompile(`startsWith\s*\(\s*['"](?:http|//|https)`)

// Deser safety patterns
var jsScJSONParse = regexp.MustCompile(`JSON\.parse\s*\(`)
var jsScYAMLSafe = regexp.MustCompile(`yaml\.safeLoad\s*\(|YAML\.parse\s*\(`)

// SSTI safety patterns
var jsScEJSStatic = regexp.MustCompile(`ejs\.render\s*\(\s*['"]`)
var jsScResRender = regexp.MustCompile(`res\.render\s*\(\s*['"]`)

// jsScHandlebarsStatic only matches when the FIRST ARGUMENT to compile is a
// string literal (`Handlebars.compile("Hello, {{name}}!")`). The earlier
// pattern (which matched any `Handlebars.compile(`) over-suppressed
// findings emitted on the same line as a non-literal call — the very thing
// the SSTI rule is meant to catch.
var jsScHandlebarsStatic = regexp.MustCompile(`Handlebars\.compile\s*\(\s*['"\x60]`)

// --- Per-CWE guard checks ---

// jsScHTTPRequestQuery matches `.query(` calls where the receiver is a
// HTTP request / context object — Hono `c.req.query`, Express
// `req.query` (when invoked), Koa `ctx.request.query`, Fastify
// `request.query`, etc. These return URL query-string parameters, not
// SQL results, so CWE-89 doesn't apply. Surfaced on honojs/hono itself
// (index.ts:49 fires Critical CWE-89 on `c.req.query()`).
var jsScHTTPRequestQuery = regexp.MustCompile(
	`(?:\b(?:c|ctx|context)\.req(?:uest)?\.query\s*\(|` +
		`\breq(?:uest)?\.query\s*\(|` +
		`\bcontext\.query\s*\()`,
)

func jsScanHasSQLGuard(lines []string, sinkLine int) bool {
	if sinkLine >= 0 && sinkLine < len(lines) {
		// HTTP request-query accessor on the same line — never SQL.
		if jsScHTTPRequestQuery.MatchString(lines[sinkLine]) {
			return true
		}
	}
	for i := max(0, sinkLine-5); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScParamQuery.MatchString(line) || jsScKnexBuilder.MatchString(line) ||
			jsScKnexRawSafe.MatchString(line) || jsScSequelize.MatchString(line) ||
			jsScPrisma.MatchString(line) {
			return true
		}
	}
	return jsScanHasTypeCoercion(lines, sinkLine) || jsScanHasAllowlist(lines, sinkLine)
}

func jsScanHasXSSGuard(lines []string, sinkLine int) bool {
	// JSON-context signals (res.json / JSON.stringify / application/json
	// content-type) describe how THIS response is encoded — they only
	// neutralize XSS for the value they wrap on their own line. Matching
	// them anywhere in a raw look-back window let a JSON response on a
	// *sibling* statement or branch suppress a genuine reflected-XSS sink
	// nearby (e.g. an `if (json) res.json(x); else res.send('<h1>'+x)`
	// handler dropped the real CWE-79 to zero). Scope them to the sink line.
	if sinkLine >= 0 && sinkLine < len(lines) {
		sl := lines[sinkLine]
		if jsScResJSON.MatchString(sl) || jsScJSONStringify.MatchString(sl) ||
			jsScContentType.MatchString(sl) {
			return true
		}
	}
	// HTML value-sanitizers (escapeHtml/DOMPurify.sanitize/validator.escape/…)
	// transform the tainted value, which may be assigned to a local on one
	// line and used in the sink a line or two later — a bounded look-back is
	// appropriate for these.
	for i := max(0, sinkLine-5); i <= sinkLine && i < len(lines); i++ {
		if jsScHTMLSanitizer.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

func jsScanHasCmdiGuard(lines []string, sinkLine int) bool {
	hasSpawn := false
	hasShellTrue := false
	for i := max(0, sinkLine-5); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScExecFile.MatchString(line) || jsScDNS.MatchString(line) ||
			jsScFsAPI.MatchString(line) {
			return true
		}
		if jsScSpawnSafe.MatchString(line) {
			hasSpawn = true
		}
		if jsScShellTrue.MatchString(line) {
			hasShellTrue = true
		}
	}
	// spawn() is safe only without shell: true
	if hasSpawn && !hasShellTrue {
		return true
	}
	return jsScanHasTypeCoercion(lines, sinkLine) ||
		jsScanHasAllowlist(lines, sinkLine) ||
		jsScanHasRegexGuard(lines, sinkLine)
}

func jsScanHasPathGuard(lines []string, sinkLine int) bool {
	hasResolve := false
	hasStartsWith := false
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScPathBasename.MatchString(line) || jsScSendFileRoot.MatchString(line) {
			return true
		}
		if jsScPathResolve.MatchString(line) {
			hasResolve = true
		}
		if jsScStartsWith.MatchString(line) {
			hasStartsWith = true
		}
	}
	if hasResolve && hasStartsWith {
		return true
	}
	return jsScanHasTypeCoercion(lines, sinkLine) ||
		jsScanHasAllowlist(lines, sinkLine) ||
		jsScanHasRegexGuard(lines, sinkLine)
}

// jsScHardcodedBaseURL matches hardcoded base URL constants used to prefix user path
var jsScHardcodedBaseURL = regexp.MustCompile(`(?:const|let|var)\s+\w+\s*=\s*['"]https?://`)

// jsScRegexReplace matches .replace() with regex to strip dangerous chars
var jsScRegexReplace = regexp.MustCompile(`\.replace\s*\(\s*/[^/]+/`)

func jsScanHasSSRFGuard(lines []string, sinkLine int) bool {
	hasURLParse := false
	hasHostCheck := false
	hasHardcodedBase := false
	hasRegexReplace := false
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScValidatorIsURL.MatchString(line) {
			return true
		}
		if jsScNewURL.MatchString(line) {
			hasURLParse = true
		}
		if jsScHostname.MatchString(line) {
			hasHostCheck = true
		}
		if jsScHardcodedBaseURL.MatchString(line) {
			hasHardcodedBase = true
		}
		if jsScRegexReplace.MatchString(line) {
			hasRegexReplace = true
		}
	}
	if hasURLParse && hasHostCheck {
		return true
	}
	// Hardcoded base URL + regex sanitization of the path component
	if hasHardcodedBase && hasRegexReplace {
		return true
	}
	return jsScanHasAllowlist(lines, sinkLine) ||
		jsScanHasRegexGuard(lines, sinkLine)
}

func jsScanHasNoSQLGuard(lines []string, sinkLine int, ruleID string) bool {
	for i := max(0, sinkLine-5); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScMongoSanitize.MatchString(line) || jsScSchemaValid.MatchString(line) ||
			jsScEqOperator.MatchString(line) {
			return true
		}
	}
	// BATOU-NOSQL-001 is the MongoDB `$where` rule: the tainted value is
	// interpolated (template literal / string concat) into a JavaScript
	// *expression* that Mongo evaluates server-side. A numeric coercion of
	// some *other* nearby variable (e.g. `parseInt(userId)` while the raw
	// `${threshold}` is what reaches `$where`) does NOT neutralize it, and
	// the broad lookback also matches `parseInt`/`Number` appearing inside a
	// /* ... */ comment block (the FP filter operates on raw text). Require
	// the coercion to wrap the value ON the sink line itself for `$where`;
	// only the operator/raw rules (NOSQL-002/003) keep the broad fallback,
	// where `find({ id: parseInt(req.query.id) })` is genuinely safe.
	if ruleID == "BATOU-NOSQL-001" {
		return sinkLine >= 0 && sinkLine < len(lines) &&
			jsScTypeCoerce.MatchString(lines[sinkLine])
	}
	return jsScanHasTypeCoercion(lines, sinkLine)
}

func jsScanHasDeserGuard(lines []string, sinkLine int) bool {
	end := sinkLine + 3
	if end > len(lines) {
		end = len(lines)
	}
	for i := max(0, sinkLine-10); i < end; i++ {
		line := lines[i]
		if jsScJSONParse.MatchString(line) || jsScYAMLSafe.MatchString(line) ||
			jsScSchemaValid.MatchString(line) {
			return true
		}
	}
	return jsScanHasAllowlist(lines, sinkLine)
}

func jsScanHasSSTIGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-5); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScEJSStatic.MatchString(line) || jsScResRender.MatchString(line) ||
			jsScHandlebarsStatic.MatchString(line) || jsScResJSON.MatchString(line) ||
			jsScJSONStringify.MatchString(line) {
			return true
		}
	}
	return jsScanHasAllowlist(lines, sinkLine)
}

func jsScanHasRedirectGuard(lines []string, sinkLine int) bool {
	hasURLParse := false
	hasCheck := false
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScRelativeGuard.MatchString(line) {
			return true
		}
		if jsScNewURL.MatchString(line) {
			hasURLParse = true
		}
		if jsScHostname.MatchString(line) || jsScStartsWith.MatchString(line) {
			hasCheck = true
		}
	}
	if hasURLParse && hasCheck {
		return true
	}
	return jsScanHasAllowlist(lines, sinkLine) ||
		jsScanHasRegexGuard(lines, sinkLine)
}

// --- Shared helpers ---

func jsScanHasTypeCoercion(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		if jsScTypeCoerce.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

func jsScanHasAllowlist(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-15); i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsScAllowlist.MatchString(line) || jsScMapLookup.MatchString(line) {
			return true
		}
	}
	return false
}

func jsScanHasRegexGuard(lines []string, sinkLine int) bool {
	for i := max(0, sinkLine-10); i <= sinkLine && i < len(lines); i++ {
		if jsScRegexGuard.MatchString(lines[i]) {
			return true
		}
	}
	return false
}
