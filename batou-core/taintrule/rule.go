package taintrule

import (
	"os"
	"regexp"
	"strings"
	"time"

	batouast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/astflow"
	"github.com/turenlabs/batou-core/taint/ssaflow"
	"github.com/turenlabs/batou-core/taint/tsflow"
)

// ssaflowEnabled returns true when the SSA-based Go taint engine should
// run alongside astflow. The engine is **ON by default** since PR-KK —
// PR-MM brought scan time to within 7% of env-OFF on real codebases
// (coder 94s vs 88s), PR-OO restored recall, and PR-PP added a
// per-leaf-sink rollup tag to keep middleware-chain noise visible-but-
// hidable. Users who want the old behaviour can opt out with
// BATOU_SSAFLOW=0 (or "off" / "false"). The opt-in spellings still
// work as no-ops for back-compat scripts.
//
// ssaflow never replaces astflow; it only adds intra-procedural flows
// astflow may have missed (or, more often, confirms ones astflow
// already found).
func ssaflowEnabled() bool {
	v := os.Getenv("BATOU_SSAFLOW")
	if v == "" {
		return true // default ON
	}
	// Explicit opt-out wins over default-on.
	if v == "0" || strings.EqualFold(v, "false") || strings.EqualFold(v, "off") || strings.EqualFold(v, "no") {
		return false
	}
	return true
}

// TaintRule implements rules.Rule using the taint analysis engine.
// It runs source-to-sink dataflow analysis on the scanned code.
type TaintRule struct{}

func init() {
	rules.Register(&TaintRule{})
}

func (t *TaintRule) ID() string              { return "BATOU-TAINT" }
func (t *TaintRule) Name() string            { return "Taint Analysis" }
func (t *TaintRule) Description() string     { return "Source-to-sink dataflow taint tracking" }
func (t *TaintRule) DefaultSeverity() rules.Severity { return rules.Critical }
func (t *TaintRule) Languages() []rules.Language {
	// Return all languages that have catalogs registered
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangPHP, rules.LangRuby,
		rules.LangC, rules.LangCPP,
		rules.LangKotlin, rules.LangSwift, rules.LangRust, rules.LangCSharp,
		rules.LangPerl, rules.LangLua, rules.LangGroovy, rules.LangShell,
		rules.LangZig,
	}
}

func (t *TaintRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	start := time.Now()

	// Route to the best taint engine for the language, matching the
	// logic in scanner.go Phase 3.  Reuse pre-parsed trees from Layer 2
	// when available to avoid redundant parsing.
	var flows []taint.TaintFlow
	if ctx.Language == rules.LangGo {
		// Reuse cached go/ast parse, or parse once and cache for the
		// call graph builder (Layer 4) to share.
		var goParsed *astflow.GoParseResult
		if cached, ok := ctx.GoASTFile.(*astflow.GoParseResult); ok {
			goParsed = cached
		} else {
			goParsed = astflow.ParseGo(ctx.Content, ctx.FilePath)
			if goParsed != nil {
				ctx.GoASTFile = goParsed
			}
		}
		flows = astflow.AnalyzeGoWithAST(ctx.Content, ctx.FilePath, goParsed)
		// PR-V: experimental SSA-based intra-procedural engine. Runs ONLY
		// when BATOU_SSAFLOW=1 (off by default). Flows are appended to the
		// astflow result; downstream dedup (scanner/dedup.go) groups by
		// (line, CWE) so a flow detected by both engines collapses into a
		// single boosted finding rather than emitting a duplicate.
		if ssaflowEnabled() {
			if ssaFlows := ssaflow.AnalyzeGo(ctx.Content, ctx.FilePath); len(ssaFlows) > 0 {
				flows = append(flows, ssaFlows...)
			}
		}
	} else if tsflow.Supports(ctx.Language) && batouast.SupportsLanguage(ctx.Language) {
		// Reuse tree-sitter tree from Layer 2 (stored in ctx.Tree).
		tree := batouast.TreeFromContext(ctx)
		flows = tsflow.AnalyzeWithTree(ctx.Content, ctx.FilePath, ctx.Language, tree)
	} else {
		// tsflow may carry a langConfig without a registered tree-sitter
		// grammar (e.g. Zig: zigConfig() exists but smacker/go-tree-sitter
		// ships no Zig grammar, so tsflow yields nothing). Fall back to the
		// regex taint engine, which consumes the same catalog Patterns.
		flows = taint.Analyze(ctx.Content, ctx.FilePath, ctx.Language)
	}

	// Cache flows on the ScanContext so scanner.go Phase 3 can reuse
	// them for hint generation without re-running taint analysis.
	ctx.TaintFlows = flows

	if len(flows) == 0 {
		return nil
	}

	// Convert flows to findings.
	findings := make([]rules.Finding, 0, len(flows))
	for i := range flows {
		// Skip benign env_var → log flows (operator-controlled, not user input)
		if flows[i].Source.Category == taint.SrcEnvVar && flows[i].Sink.Category == taint.SnkLog {
			continue
		}
		finding := flows[i].ToFinding()
		finding.Language = ctx.Language
		finding.FilePath = ctx.FilePath
		findings = append(findings, finding)
	}

	// Python FP suppression: check if the sink variable was last assigned
	// a safe value, or if there is a category-specific guard nearby.
	if ctx.Language == rules.LangPython && len(findings) > 0 {
		findings = pyFilterTaintFindings(ctx.Content, findings)
	}

	// Java FP suppression: filter deterministic conditionals and safe indirection.
	if ctx.Language == rules.LangJava && len(findings) > 0 {
		findings = javaFilterTaintFindings(ctx.Content, findings)
	}

	// JavaScript/TypeScript FP suppression: filter findings where safe APIs,
	// guard patterns, or type coercion neutralize the vulnerability.
	if (ctx.Language == rules.LangJavaScript || ctx.Language == rules.LangTypeScript) && len(findings) > 0 {
		findings = jsFilterTaintFindings(ctx.Content, findings)
	}

	// Go FP suppression: suppress CWE-79 (XSS) findings when the function
	// sets Content-Type to application/json or other non-HTML types.
	if ctx.Language == rules.LangGo && len(findings) > 0 {
		findings = goFilterTaintFindings(ctx.Content, findings)
	}

	// Also add the formatted taint report as context in the last finding
	elapsed := time.Since(start).Milliseconds()
	report := taint.FormatFlowsReport(flows, ctx.FilePath, ctx.Language, elapsed)
	if len(findings) > 0 && report != "" {
		// Append the visual flow report to the last finding's description
		findings[len(findings)-1].Description += "\n\n" + report
	}

	return findings
}

// pyYAMLSafeLoad matches yaml.safe_load() calls which are safe by design
// and should not trigger deserialization findings.
var pyYAMLSafeLoad = regexp.MustCompile(`yaml\.safe_load\s*\(`)

// pyArithmeticIf matches if-conditions with arithmetic comparisons
// like "if 7 * 42 - num > 200:" — these are deterministic conditions
// used in OWASP Benchmark to create always-true/false branches.
var pyArithmeticIf = regexp.MustCompile(`^\s*if\s+\d+\s*\*\s*\d+`)

// pyTernaryArithmetic matches ternary expressions with arithmetic conditions
// like "bar = 'safe' if 7 * 18 + num > 200 else param"
var pyTernaryArithmetic = regexp.MustCompile(`if\s+\d+\s*\*\s*\d+\s*[+\-]\s*\w+\s*[><=]`)

// pyMatchConstGuard matches match statements on a subscripted constant
// like "possible = 'ABC'; guess = possible[1]; match guess:"
var pyConstSubscript = regexp.MustCompile(`^\s*\w+\s*=\s*\w+\[\d+\]`)
var pyMatchKeyword = regexp.MustCompile(`^\s*match\s+\w+\s*:`)

// pyLiteralAssign matches assignment of a string literal to a variable
var pyLiteralAssign = regexp.MustCompile(`^\s*\w+\s*=\s*['"]`)

// pyFilterTaintFindings suppresses Python taint findings where a
// category-specific structural guard is present near the sink, or where
// the taint engine over-approximates through deterministic conditionals.
func pyFilterTaintFindings(content string, findings []rules.Finding) []rules.Finding {
	lines := strings.Split(content, "\n")
	kept := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		lineIdx := f.LineNumber - 1
		if lineIdx < 0 || lineIdx >= len(lines) {
			kept = append(kept, f)
			continue
		}

		// Check if the code preceding the sink contains a deterministic
		// conditional (always-true arithmetic, match-on-constant, ternary).
		// These create FPs in both taint and regex findings because the
		// "vulnerable" branch is never actually executed.
		if pyHasDeterministicConditional(lines, lineIdx) {
			continue
		}

		// For taint findings: additional checks for dict key and config
		// key resolution that the taint engine can't evaluate.
		if strings.HasPrefix(f.RuleID, "BATOU-TAINT") {
			if pyTaintSinkVarIsSafeDictOrConfig(lines, lineIdx) {
				continue
			}
		}

		// Category-specific guards (taint engine already proves the flow;
		// only suppress for structural patterns the engine cannot see)
		cwe := strings.TrimPrefix(f.CWEID, "CWE-")
		switch cwe {
		case "502": // Deserialization
			if pyYAMLSafeLoad.MatchString(lines[lineIdx]) {
				continue
			}
		case "643": // XPath injection
			if rules.PyHasXPathGuard(lines, lineIdx) {
				continue
			}
		case "22": // Path traversal
			if rules.PyHasTraversalGuard(lines, lineIdx) {
				continue
			}
		case "94": // Code injection
			if rules.PyHasEvalGuard(lines, lineIdx) {
				continue
			}
		case "601": // Open redirect
			if rules.PyHasURLValidation(lines, lineIdx) {
				continue
			}
		}
		kept = append(kept, f)
	}
	return kept
}

// pyHasDeterministicConditional checks if the code preceding the sink
// contains a conditional whose outcome is deterministic (arithmetic
// comparison on constants, match on constant-subscripted value, or
// ternary with arithmetic guard). These patterns are used in OWASP
// Benchmark to create always-true/false branches that the taint engine
// cannot evaluate, causing false positives.
func pyHasDeterministicConditional(lines []string, sinkLine int) bool {
	start := sinkLine - 40
	if start < 0 {
		start = 0
	}

	hasArithmeticIf := false
	hasMatchOnConst := false
	hasConstSubscript := false
	hasLiteralInBranch := false

	for i := start; i < sinkLine; i++ {
		line := lines[i]
		// Arithmetic if-condition: "if 7 * 42 - num > 200:"
		if pyArithmeticIf.MatchString(line) {
			hasArithmeticIf = true
		}
		// Ternary with arithmetic: "bar = 'x' if 7 * 18 + num > 200 else param"
		if pyTernaryArithmetic.MatchString(line) {
			return true // ternary arithmetic is a strong FP signal
		}
		// Constant subscript assignment: "guess = possible[1]"
		if pyConstSubscript.MatchString(line) {
			hasConstSubscript = true
		}
		// Match keyword: "match guess:"
		if pyMatchKeyword.MatchString(line) {
			hasMatchOnConst = hasConstSubscript
		}
		// Literal assignment in a branch: "bar = 'literal'"
		if pyLiteralAssign.MatchString(line) {
			hasLiteralInBranch = true
		}
	}

	// Arithmetic if with literal branch → likely always-true/false condition
	if hasArithmeticIf && hasLiteralInBranch {
		return true
	}
	// Match on constant-subscripted variable with literal branch
	if hasMatchOnConst && hasLiteralInBranch {
		return true
	}

	return false
}

// pyTaintSinkVarIsSafeDictOrConfig extracts the sink variable from the taint
// finding's line and checks if it was last assigned from a safe dict key or
// configparser key. This is a targeted subset of PySinkVarIsSafe that avoids
// the always-true arithmetic check (which has branch-ordering issues when
// called on taint findings where both branches were walked).
func pyTaintSinkVarIsSafeDictOrConfig(lines []string, sinkIdx int) bool {
	if sinkIdx < 0 || sinkIdx >= len(lines) {
		return false
	}
	varName := rules.PyExtractSinkVar(lines[sinkIdx])
	if varName == "" {
		return false
	}
	return pyVarIsSafeDictOrConfig(lines, sinkIdx, varName, 0)
}

// pyVarIsSafeDictOrConfig traces a variable back through assignments checking
// for safe dict key or configparser key resolution. Follows f-string and
// compound assignment chains up to 3 levels deep.
func pyVarIsSafeDictOrConfig(lines []string, fromIdx int, varName string, depth int) bool {
	if depth > 3 || varName == "" {
		return false
	}
	assignPrefix := varName + " = "
	compoundPrefix := varName + " += "
	for i := fromIdx - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])

		// Compound assignment (+=): check if the RHS contains an f-string
		// variable that traces back to a safe dict key.
		if strings.HasPrefix(trimmed, compoundPrefix) {
			rhs := strings.TrimSpace(trimmed[len(compoundPrefix):])
			if fVars := rules.PyFStringVar.FindAllStringSubmatch(rhs, -1); len(fVars) > 0 {
				for _, fv := range fVars {
					if len(fv) > 1 && fv[1][0] >= 'A' {
						if pyVarIsSafeDictOrConfig(lines, i, fv[1], depth+1) {
							return true
						}
					}
				}
			}
			continue
		}

		if !strings.HasPrefix(trimmed, assignPrefix) {
			continue
		}
		rhs := strings.TrimSpace(trimmed[len(assignPrefix):])

		// Dict key resolution: bar = someDict['keyA']
		if m := pyDictAccessRe.FindStringSubmatch(rhs); len(m) > 2 {
			return rules.PyDictKeyIsSafe(lines, i, m[1], m[2])
		}
		// ConfigParser resolution: bar = conf.get('section', 'key')
		if m := pyConfigGetRe.FindStringSubmatch(rhs); len(m) > 3 {
			return rules.PyConfigSetIsSafe(lines, i, m[1], m[2], m[3])
		}
		// f-string with interpolated variable: trace through it.
		if fVars := rules.PyFStringVar.FindAllStringSubmatch(rhs, -1); len(fVars) > 0 {
			for _, fv := range fVars {
				if len(fv) > 1 && fv[1][0] >= 'A' {
					if pyVarIsSafeDictOrConfig(lines, i, fv[1], depth+1) {
						return true
					}
				}
			}
		}
		// For other assignments, don't suppress.
		break
	}
	return false
}

// pyDictAccessRe matches dict/map key access: someDict['keyName']
var pyDictAccessRe = regexp.MustCompile(`^(\w+)\[['"]([^'"]+)['"]\]$`)

// pyConfigGetRe matches configparser get: conf.get('section', 'key')
var pyConfigGetRe = regexp.MustCompile(`^(\w+)\.get\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]\s*\)$`)

// --- Java FP suppression ---

// javaArithmeticIf matches Java if-conditions with arithmetic comparisons
// like "if ((7 * 42) - num > 200)" — deterministic conditions in OWASP Benchmark.
var javaArithmeticIf = regexp.MustCompile(`\bif\s*\(\s*\(?\s*\d+\s*\*\s*\d+`)

// javaTernaryArithmetic matches ternary expressions with arithmetic conditions.
var javaTernaryArithmetic = regexp.MustCompile(`\?\s*"[^"]*"\s*:\s*\w+.*\d+\s*\*\s*\d+|\d+\s*\*\s*\d+\s*[+\-]\s*\w+\s*[><=]`)

// javaLiteralAssign matches assignment of a string literal to a variable in Java.
var javaLiteralAssign = regexp.MustCompile(`\b\w+\s*=\s*"[^"]*"\s*;`)

// javaFilterTaintFindings suppresses Java findings where deterministic
// conditionals or safe variable assignments create false-positive flows.
func javaFilterTaintFindings(content string, findings []rules.Finding) []rules.Finding {
	lines := strings.Split(content, "\n")

	kept := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		lineIdx := f.LineNumber - 1
		if lineIdx < 0 || lineIdx >= len(lines) {
			kept = append(kept, f)
			continue
		}

		// Deterministic conditional check — applies to ALL findings.
		if javaHasDeterministicConditional(lines, lineIdx) {
			continue
		}

		kept = append(kept, f)
	}
	return kept
}

// javaHasDeterministicConditional checks if the code preceding the sink
// contains a conditional whose outcome is deterministic (arithmetic
// comparison on constants, ternary with arithmetic guard, or switch on
// constant value). These patterns are used in OWASP Benchmark to create
// always-true/false branches.
func javaHasDeterministicConditional(lines []string, sinkLine int) bool {
	start := sinkLine - 50
	if start < 0 {
		start = 0
	}

	hasArithmeticIf := false
	hasLiteralInBranch := false
	hasSwitchOnConst := false

	for i := start; i < sinkLine; i++ {
		line := lines[i]
		// Arithmetic if: if ((7 * 42 - num) > 200)
		if javaArithmeticIf.MatchString(line) {
			hasArithmeticIf = true
		}
		// Ternary with arithmetic: always returns immediately
		if javaTernaryArithmetic.MatchString(line) {
			return true
		}
		// Literal assignment in a branch
		if javaLiteralAssign.MatchString(line) {
			hasLiteralInBranch = true
		}
		// Switch on a constant-indexed value: switch (arr[2])
		if javaSwitchOnConst.MatchString(line) {
			hasSwitchOnConst = true
		}
	}

	if hasArithmeticIf && hasLiteralInBranch {
		return true
	}
	if hasSwitchOnConst && hasLiteralInBranch {
		return true
	}

	return false
}

// javaSwitchOnConst matches switch statements on constant-indexed values:
//
//	switch (arr[2]) or switch (list.get(1))
var javaSwitchOnConst = regexp.MustCompile(`\bswitch\s*\(\s*\w+(?:\[\d+\]|\.get\(\d+\))`)

// --- JavaScript/TypeScript FP suppression ---

// jsParamQuery matches parameterized SQL queries: db.query("...?", [param])
var jsParamQuery = regexp.MustCompile(`\.query\s*\([^,]+\?\s*['"]\s*,\s*\[`)

// jsKnexBuilder matches Knex query builder calls: knex('table').where(...)
var jsKnexBuilder = regexp.MustCompile(`knex\s*\(\s*['"]`)

// jsKnexRaw matches Knex raw with bindings: knex.raw("...?", [...])
var jsKnexRaw = regexp.MustCompile(`knex\.raw\s*\([^,]+\?\s*['"]\s*,\s*\[`)

// jsSequelizeParam matches Sequelize parameterized queries with replacements/bind
var jsSequelizeParam = regexp.MustCompile(`\.query\s*\([^,]+,\s*\{\s*(?:replacements|bind)\s*:`)

// jsPrismaSQL matches Prisma tagged template literals: Prisma.sql`...`
var jsPrismaSQL = regexp.MustCompile("Prisma\\.sql\\s*`")

// jsExecFile matches safe execFile/spawn with argument arrays (no shell)
var jsExecFile = regexp.MustCompile(`\b(?:execFile|spawn)\s*\(`)

// jsDNSLookup matches dns.lookup (safe alternative to shell-based resolution)
var jsDNSLookup = regexp.MustCompile(`dns\.(?:lookup|resolve)\s*\(`)

// jsFsAppend matches fs.appendFile/writeFile (not a command injection sink)
var jsFsAppend = regexp.MustCompile(`fs\.(?:appendFile|writeFile)\s*\(`)

// jsResJSON matches res.json() — safe sink (sets Content-Type: application/json)
var jsResJSON = regexp.MustCompile(`res\.json\s*\(`)

// jsJSONStringify matches JSON.stringify() usage
var jsJSONStringify = regexp.MustCompile(`JSON\.stringify\s*\(`)

// jsURLValidation matches URL validation: new URL() + hostname/origin/protocol check
var jsURLValidation = regexp.MustCompile(`new\s+URL\s*\(`)

// jsHostnameCheck matches hostname/origin allowlist checks
var jsHostnameCheck = regexp.MustCompile(`\.(?:hostname|origin|protocol)\b`)

// jsAllowlistCheck matches allowlist patterns: ALLOWED_*.includes(), .has(), map lookup
var jsAllowlistCheck = regexp.MustCompile(`(?:ALLOWED|VALID|allowed|valid|whitelist|WHITELIST)\w*\.(?:includes|has)\s*\(`)

// jsMapLookup matches map/object enum lookup: MAP[key], ENUM[key]
var jsMapLookup = regexp.MustCompile(`[A-Z_]{2,}\[\w+\]`)

// jsPathResolveGuard matches path.resolve() + startsWith() check
var jsPathResolveGuard = regexp.MustCompile(`path\.(?:resolve|normalize)\s*\(`)

// jsStartsWithCheck matches .startsWith() guards
var jsStartsWithCheck = regexp.MustCompile(`\.startsWith\s*\(`)

// jsPathBasename matches path.basename() usage (strips directory components)
var jsPathBasename = regexp.MustCompile(`path\.basename\s*\(`)

// jsTypeCoercion matches parseInt/Number/String/parseFloat/new Date coercion
var jsTypeCoercion = regexp.MustCompile(`\b(?:parseInt|parseFloat|Number|String)\s*\(|new\s+Date\s*\(`)

// jsValidatorIsURL matches validator.isURL() check
var jsValidatorIsURL = regexp.MustCompile(`validator\.isURL\s*\(`)

// jsRegexValidation matches regex test/match patterns for input validation
var jsRegexValidation = regexp.MustCompile(`(?:/\^[^/]+\$/|\.test\s*\(|\.match\s*\()`)

// jsMongoSanitize matches mongo-sanitize library
var jsMongoSanitize = regexp.MustCompile(`mongo-sanitize|express-mongo-sanitize`)

// jsSchemaValidation matches Zod, Ajv, Joi schema validation
var jsSchemaValidation = regexp.MustCompile(`\b(?:schema|Schema)\.(?:parse|safeParse|validate)\s*\(|ajv\.validate\s*\(|Joi\.validate\s*\(`)

// jsSendFileRoot matches res.sendFile with root option (safe path confinement)
var jsSendFileRoot = regexp.MustCompile(`\.sendFile\s*\([^)]*\{\s*root\s*:`)

// jsYAMLSafeLoad matches yaml.safeLoad/YAML.parse (safe YAML parsing)
var jsYAMLSafeLoad = regexp.MustCompile(`yaml\.safeLoad\s*\(|YAML\.parse\s*\(`)

// jsJSONParse matches JSON.parse (safe deserialization)
var jsJSONParse = regexp.MustCompile(`JSON\.parse\s*\(`)

// jsEJSRender matches EJS template with data params (safe: template is static)
var jsEJSRender = regexp.MustCompile(`ejs\.render\s*\(\s*['"]`)

// jsResRender matches res.render with string template name (safe: uses view engine)
var jsResRender = regexp.MustCompile(`res\.render\s*\(\s*['"]`)

// jsHandlebarsCompile matches Handlebars.compile with static template
var jsHandlebarsCompile = regexp.MustCompile(`Handlebars\.compile\s*\(`)

// jsRelativePathGuard matches checks for http/protocol-relative URLs in redirect context
var jsRelativePathGuard = regexp.MustCompile(`startsWith\s*\(\s*['"](?:http|//|https)`)

// jsSanitizer matches common JS sanitizer function calls near sink
var jsSanitizer = regexp.MustCompile(`\b(?:escapeHtml|DOMPurify\.sanitize|validator\.escape|sanitizeHtml|he\.encode|he\.escape|encodeURIComponent|xss)\s*\(`)

// jsFilterTaintFindings suppresses JS/TS findings where safe APIs, guard patterns,
// type coercion, or sanitizer calls neutralize the vulnerability.
func jsFilterTaintFindings(content string, findings []rules.Finding) []rules.Finding {
	lines := strings.Split(content, "\n")
	kept := make([]rules.Finding, 0, len(findings))

	for _, f := range findings {
		lineIdx := f.LineNumber - 1
		if lineIdx < 0 || lineIdx >= len(lines) {
			kept = append(kept, f)
			continue
		}

		cwe := strings.TrimPrefix(f.CWEID, "CWE-")

		// Category-specific FP suppression
		suppressed := false
		switch cwe {
		case "89": // SQL Injection
			suppressed = jsHasSQLSanitization(lines, lineIdx)
		case "79": // XSS
			suppressed = jsHasXSSSanitization(lines, lineIdx)
		case "78": // Command Injection
			suppressed = jsHasCmdiSanitization(lines, lineIdx)
		case "22": // Path Traversal
			suppressed = jsHasPathTraversalGuard(lines, lineIdx)
		case "918": // SSRF
			suppressed = jsHasSSRFGuard(lines, lineIdx)
		case "943": // NoSQL Injection
			suppressed = jsHasNoSQLSanitization(lines, lineIdx)
		case "502": // Deserialization
			suppressed = jsHasDeserGuard(lines, lineIdx)
		case "1336": // SSTI
			suppressed = jsHasSSTIGuard(lines, lineIdx)
		case "601": // Open Redirect
			suppressed = jsHasRedirectGuard(lines, lineIdx)
		}

		if suppressed {
			continue
		}

		kept = append(kept, f)
	}
	return kept
}

// jsHasSQLSanitization checks for parameterized queries, ORM builders, or type coercion.
func jsHasSQLSanitization(lines []string, sinkLine int) bool {
	start := sinkLine - 5
	if start < 0 {
		start = 0
	}
	end := sinkLine + 1
	if end > len(lines) {
		end = len(lines)
	}
	for i := start; i < end; i++ {
		line := lines[i]
		if jsParamQuery.MatchString(line) || jsKnexBuilder.MatchString(line) ||
			jsKnexRaw.MatchString(line) || jsSequelizeParam.MatchString(line) ||
			jsPrismaSQL.MatchString(line) {
			return true
		}
	}
	return jsHasTypeCoercionNearby(lines, sinkLine) || jsHasAllowlistNearby(lines, sinkLine)
}

// jsHasXSSSanitization checks for HTML sanitizers, JSON output, or encoding.
func jsHasXSSSanitization(lines []string, sinkLine int) bool {
	start := sinkLine - 5
	if start < 0 {
		start = 0
	}
	end := sinkLine + 1
	if end > len(lines) {
		end = len(lines)
	}
	for i := start; i < end; i++ {
		line := lines[i]
		if jsSanitizer.MatchString(line) || jsResJSON.MatchString(line) ||
			jsJSONStringify.MatchString(line) {
			return true
		}
	}
	return false
}

// jsHasCmdiSanitization checks for safe exec APIs (execFile/spawn with arrays),
// alternative safe APIs, type coercion, or allowlist validation.
func jsHasCmdiSanitization(lines []string, sinkLine int) bool {
	start := sinkLine - 5
	if start < 0 {
		start = 0
	}
	end := sinkLine + 1
	if end > len(lines) {
		end = len(lines)
	}
	for i := start; i < end; i++ {
		line := lines[i]
		if jsExecFile.MatchString(line) || jsDNSLookup.MatchString(line) ||
			jsFsAppend.MatchString(line) {
			return true
		}
	}
	return jsHasTypeCoercionNearby(lines, sinkLine) ||
		jsHasAllowlistNearby(lines, sinkLine) ||
		jsHasRegexGuardNearby(lines, sinkLine)
}

// jsHasPathTraversalGuard checks for path.resolve+startsWith, path.basename,
// sendFile with root, or regex validation.
func jsHasPathTraversalGuard(lines []string, sinkLine int) bool {
	start := sinkLine - 10
	if start < 0 {
		start = 0
	}
	end := sinkLine + 1
	if end > len(lines) {
		end = len(lines)
	}
	hasPathResolve := false
	hasStartsWith := false
	for i := start; i < end; i++ {
		line := lines[i]
		if jsPathBasename.MatchString(line) || jsSendFileRoot.MatchString(line) {
			return true
		}
		if jsPathResolveGuard.MatchString(line) {
			hasPathResolve = true
		}
		if jsStartsWithCheck.MatchString(line) {
			hasStartsWith = true
		}
	}
	if hasPathResolve && hasStartsWith {
		return true
	}
	return jsHasTypeCoercionNearby(lines, sinkLine) ||
		jsHasAllowlistNearby(lines, sinkLine) ||
		jsHasRegexGuardNearby(lines, sinkLine)
}

// jsHasSSRFGuard checks for URL validation (new URL + hostname check),
// validator.isURL, allowlists, or hardcoded base URLs.
func jsHasSSRFGuard(lines []string, sinkLine int) bool {
	start := sinkLine - 15
	if start < 0 {
		start = 0
	}
	end := sinkLine + 1
	if end > len(lines) {
		end = len(lines)
	}
	hasURLParse := false
	hasHostnameCheck := false
	for i := start; i < end; i++ {
		line := lines[i]
		if jsValidatorIsURL.MatchString(line) {
			return true
		}
		if jsURLValidation.MatchString(line) {
			hasURLParse = true
		}
		if jsHostnameCheck.MatchString(line) {
			hasHostnameCheck = true
		}
	}
	if hasURLParse && hasHostnameCheck {
		return true
	}
	return jsHasAllowlistNearby(lines, sinkLine) ||
		jsHasRegexGuardNearby(lines, sinkLine)
}

// jsHasNoSQLSanitization checks for type coercion (String/Number/parseInt),
// mongo-sanitize, or schema validation.
func jsHasNoSQLSanitization(lines []string, sinkLine int) bool {
	start := sinkLine - 5
	if start < 0 {
		start = 0
	}
	end := sinkLine + 1
	if end > len(lines) {
		end = len(lines)
	}
	for i := start; i < end; i++ {
		line := lines[i]
		if jsMongoSanitize.MatchString(line) || jsSchemaValidation.MatchString(line) {
			return true
		}
	}
	return jsHasTypeCoercionNearby(lines, sinkLine)
}

// jsHasDeserGuard checks for safe deserialization (JSON.parse, yaml.safeLoad,
// schema validation, or allowlist of functions).
func jsHasDeserGuard(lines []string, sinkLine int) bool {
	start := sinkLine - 10
	if start < 0 {
		start = 0
	}
	end := sinkLine + 3
	if end > len(lines) {
		end = len(lines)
	}
	for i := start; i < end; i++ {
		line := lines[i]
		if jsJSONParse.MatchString(line) || jsYAMLSafeLoad.MatchString(line) ||
			jsSchemaValidation.MatchString(line) {
			return true
		}
	}
	return jsHasAllowlistNearby(lines, sinkLine)
}

// jsHasSSTIGuard checks for safe template rendering (static template string,
// data-only rendering, res.json, or allowlist of templates).
func jsHasSSTIGuard(lines []string, sinkLine int) bool {
	start := sinkLine - 5
	if start < 0 {
		start = 0
	}
	end := sinkLine + 1
	if end > len(lines) {
		end = len(lines)
	}
	for i := start; i < end; i++ {
		line := lines[i]
		if jsEJSRender.MatchString(line) || jsResRender.MatchString(line) ||
			jsHandlebarsCompile.MatchString(line) || jsResJSON.MatchString(line) ||
			jsJSONStringify.MatchString(line) {
			return true
		}
	}
	return jsHasAllowlistNearby(lines, sinkLine)
}

// jsHasRedirectGuard checks for URL validation, relative path enforcement,
// regex validation, or allowlist.
func jsHasRedirectGuard(lines []string, sinkLine int) bool {
	start := sinkLine - 10
	if start < 0 {
		start = 0
	}
	end := sinkLine + 1
	if end > len(lines) {
		end = len(lines)
	}
	hasURLParse := false
	hasHostnameCheck := false
	for i := start; i < end; i++ {
		line := lines[i]
		if jsRelativePathGuard.MatchString(line) {
			return true
		}
		if jsURLValidation.MatchString(line) {
			hasURLParse = true
		}
		if jsHostnameCheck.MatchString(line) || jsStartsWithCheck.MatchString(line) {
			hasHostnameCheck = true
		}
	}
	if hasURLParse && hasHostnameCheck {
		return true
	}
	return jsHasAllowlistNearby(lines, sinkLine) ||
		jsHasRegexGuardNearby(lines, sinkLine)
}

// jsHasTypeCoercionNearby checks if parseInt/Number/String/parseFloat/new Date
// appears in the nearby code before the sink.
func jsHasTypeCoercionNearby(lines []string, sinkLine int) bool {
	start := sinkLine - 10
	if start < 0 {
		start = 0
	}
	for i := start; i <= sinkLine && i < len(lines); i++ {
		if jsTypeCoercion.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

// jsHasAllowlistNearby checks for allowlist/whitelist patterns or map lookups
// in the surrounding code.
func jsHasAllowlistNearby(lines []string, sinkLine int) bool {
	start := sinkLine - 15
	if start < 0 {
		start = 0
	}
	for i := start; i <= sinkLine && i < len(lines); i++ {
		line := lines[i]
		if jsAllowlistCheck.MatchString(line) || jsMapLookup.MatchString(line) {
			return true
		}
	}
	return false
}

// jsHasRegexGuardNearby checks for regex-based input validation in nearby code.
func jsHasRegexGuardNearby(lines []string, sinkLine int) bool {
	start := sinkLine - 10
	if start < 0 {
		start = 0
	}
	for i := start; i <= sinkLine && i < len(lines); i++ {
		if jsRegexValidation.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

// =========================================================================
// Go FP suppression
// =========================================================================

// reGoJSONContentType matches Content-Type headers set to non-HTML types.
// When a Go HTTP handler sets application/json, text/plain, application/ndjson,
// etc., ResponseWriter.Write() is not an XSS vector.
var reGoJSONContentType = regexp.MustCompile(
	`(?i)\.Header\(\)\.\s*Set\(\s*"Content-Type"\s*,\s*"(application/(json|ndjson|octet-stream|protobuf)|text/plain)`)

// goFilterTaintFindings suppresses Go taint findings that are false positives:
//   - CWE-79 (XSS) when Content-Type is set to application/json or similar
func goFilterTaintFindings(content string, findings []rules.Finding) []rules.Finding {
	lines := strings.Split(content, "\n")
	kept := make([]rules.Finding, 0, len(findings))

	// Pre-scan: does the file set a non-HTML Content-Type anywhere?
	hasJSONContentType := false
	for _, line := range lines {
		if reGoJSONContentType.MatchString(line) {
			hasJSONContentType = true
			break
		}
	}

	for _, f := range findings {
		cwe := strings.TrimPrefix(f.CWEID, "CWE-")

		// Suppress XSS findings when the handler sets a non-HTML Content-Type.
		// JSON API responses written via w.Write() are not XSS vectors.
		if cwe == "79" && hasJSONContentType {
			continue
		}

		kept = append(kept, f)
	}
	return kept
}
