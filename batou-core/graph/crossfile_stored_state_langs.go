// Per-language registry for the cross-file STORED-STATE channel.
//
// crossfile_stored_state.go carries the Python slice (#1221) and the
// language-agnostic WalkCrossFileStoredState driver. This file generalises
// the producer (field-write of an external source) and consumer (field-read
// into a sink) detection to the high-traffic object-oriented languages —
// Java, JavaScript/TypeScript, Ruby, C# — by reusing each language's EXISTING
// external-source / sanitizer regexes and sink catalog (the same nets the
// call-edge cross-file walk already uses). No new bare-name sources are
// invented.
//
// The canonical flow (see crossfile_stored_state.go header) is identical
// across languages; only the surface syntax of the field write/read differs:
//
//	Java / C#:           this.q = <source>   ...   sink(this.q)   (or bare q)
//	JavaScript / TS:     this.q = <source>   ...   sink(this.q)
//	Ruby:                @q = <source>        ...   sink(@q)
//	PHP (deferred):      $this->q = <source>  ...   sink($this->q)
//
// The two methods are joined by enclosing CLASS identity — the dotted
// qualifier on FuncNode.Name (`UserController.load` and `UserController.run`
// both have class `UserController`). Java, JS/TS, Ruby, and C# all encode the
// method node name as `Class.method` (builder_{java,javascript,ruby,csharp}.go),
// so the shared classQualifier() (last `.`) works for all four. PHP encodes
// `Namespace\Class::method`, which classQualifier() cannot split, so PHP is
// intentionally NOT registered here (its field-read shape `$this->q` would
// also collide with the field-write capture in ways that need a PHP-aware
// qualifier — deferred as follow-up).
//
// FP discipline is the SAME as the Python producer: the written value must be
// a genuine external catalog source (the language sourceRe), a sanitized write
// is dropped, and a field set from a method PARAMETER is not recorded (the
// sourceRe never matches a bare parameter name, so param-sourced writes fall
// out for free, exactly as in Python). Confidence stays 0.8 so a
// class-name-collision flow is a hint, not a hard block, unless the
// external-origin block gate also agrees.

package graph

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// storedStateSinkPattern is the language-neutral sink shape the stored-state
// reader scan matches against. It is the common subset of the per-language
// *SinkPattern structs (pythonSinkPattern, javascriptSinkPattern, ...), so a
// single reader loop serves every registered language.
type storedStateSinkPattern struct {
	pattern       *regexp.Regexp
	category      taint.SinkCategory
	method        string
	module        string
	requireModule bool
}

// storedStateLangConfig describes how to detect the producer (field write of
// an external source) and the consumer (field read into a sink) for one
// language. Every field reuses machinery that already exists elsewhere in the
// graph package — this struct only wires it into the stored-state channel.
type storedStateLangConfig struct {
	lang rules.Language

	// fieldWriteRe matches a single-line instance-field assignment and
	// captures (1) the field name and (2) the RHS expression. Anchored at
	// line start (after leading whitespace) so only a top-level statement
	// assignment is captured, never a field read embedded in a larger
	// expression.
	fieldWriteRe *regexp.Regexp

	// readPrefixes are the receiver-qualified prefixes a field READ takes in
	// this language (`this.`, `@`, ...). A read hit requires `<prefix><field>`
	// as a whole token so `this.q` does not match `this.query`.
	readPrefixes []string

	// sourceRe / sanitizerRe are the language's existing coarse external-source
	// and sanitizer nets (the same ones the call-edge cross-file walk uses).
	sourceRe    *regexp.Regexp
	sanitizerRe *regexp.Regexp

	// coercionRe, when set, drops a field write whose RHS coerces the value to
	// a non-injectable type (`params[:month].to_i` — an integer cannot carry a
	// payload). Channel-local so the shared sanitizer nets used by the
	// call-edge walk are untouched.
	coercionRe *regexp.Regexp

	// loadSinks returns the language's sink catalog in the neutral shape.
	loadSinks func() []storedStateSinkPattern

	// sinkNeutralises reports whether a same-line sanitizer call neutralises a
	// sink of the given category end-to-end (HTML/redirect/template/trust).
	sinkNeutralises func(taint.SinkCategory) bool

	// commentPrefixes are the line-comment markers to skip.
	commentPrefixes []string
}

// storedStateLangConfigs is the registry of languages that participate in the
// cross-file stored-state channel. Python is handled by its own
// scanPythonBodyForStoredFieldWrites path (it needs paren-continuation
// joining); the languages here use plain newline splitting.
var storedStateLangConfigs = buildStoredStateLangConfigs()

func buildStoredStateLangConfigs() map[rules.Language]storedStateLangConfig {
	cfgs := map[rules.Language]storedStateLangConfig{}

	// Java — `this.field = <source>;`. Bare-field writes (`field = <source>`)
	// are deliberately NOT captured: an unqualified assignment is ambiguous
	// with a local variable and would over-approximate. The read side accepts
	// both `this.field` and a bare `field` token (a method reading its own
	// instance field unqualified is idiomatic Java).
	javaCfg := storedStateLangConfig{
		lang:            rules.LangJava,
		fieldWriteRe:    reJavaCSharpFieldWrite,
		readPrefixes:    []string{"this."},
		sourceRe:        javaSourceExprRe,
		sanitizerRe:     javaSanitizerRe,
		loadSinks:       loadJavaStoredStateSinks,
		sinkNeutralises: javaSinkLineSanitizerNeutralises,
		commentPrefixes: []string{"//", "*"},
	}
	cfgs[rules.LangJava] = javaCfg

	// C# — `this.Field = <source>;`. Same shape as Java.
	cfgs[rules.LangCSharp] = storedStateLangConfig{
		lang:            rules.LangCSharp,
		fieldWriteRe:    reJavaCSharpFieldWrite,
		readPrefixes:    []string{"this."},
		sourceRe:        csharpSourceExprRe,
		sanitizerRe:     csharpSanitizerRe,
		loadSinks:       loadCSharpStoredStateSinks,
		sinkNeutralises: csharpSinkLineSanitizerNeutralises,
		commentPrefixes: []string{"//", "*"},
	}

	// JavaScript / TypeScript — `this.field = <source>`. The JS catalog is
	// shared between JS and TS, so both languages key off the same loader and
	// regexes; both register here.
	jsCfg := storedStateLangConfig{
		lang:            rules.LangJavaScript,
		fieldWriteRe:    reJSFieldWrite,
		readPrefixes:    []string{"this."},
		sourceRe:        javascriptSourceExprRe,
		sanitizerRe:     javascriptSanitizerRe,
		loadSinks:       loadJavaScriptStoredStateSinks,
		sinkNeutralises: jsSinkLineSanitizerNeutralises,
		commentPrefixes: []string{"//", "*"},
	}
	cfgs[rules.LangJavaScript] = jsCfg
	tsCfg := jsCfg
	tsCfg.lang = rules.LangTypeScript
	cfgs[rules.LangTypeScript] = tsCfg

	// Ruby — `@field = <source>`. The read side is the bare `@field` token.
	// coercionRe: `params[:month].to_i` (and .to_f) stores an integer/float —
	// not an injectable value (observed as the residual FP class on real Rails
	// code after the entity-lookup gate).
	cfgs[rules.LangRuby] = storedStateLangConfig{
		lang:            rules.LangRuby,
		fieldWriteRe:    reRubyFieldWrite,
		readPrefixes:    []string{"@"},
		sourceRe:        rubySourceExprRe,
		sanitizerRe:     rubySanitizerRe,
		coercionRe:      regexp.MustCompile(`\.to_[if]\b`),
		loadSinks:       loadRubyStoredStateSinks,
		sinkNeutralises: rubySinkLineSanitizerNeutralises,
		commentPrefixes: []string{"#"},
	}

	// PHP — `$this->field = <source>;` writes, `$this->field` reads. PHP
	// method nodes are named `Namespace\Class::method`, so the join works
	// off the `::`-aware classQualifier (`App\Repo::find` → "App\Repo").
	// The read prefix is `$this->` (a bare unqualified field read does not
	// exist in PHP — instance fields are always `$this->`), so no bare-read
	// path is enabled. All source / sanitizer / sink nets are the EXISTING
	// PHP cross-file regexes and sink catalog (php_sources.go / php_sinks.go
	// / php_sanitizers.go via the graph-package mirrors).
	cfgs[rules.LangPHP] = storedStateLangConfig{
		lang:            rules.LangPHP,
		fieldWriteRe:    rePHPFieldWrite,
		readPrefixes:    []string{"$this->"},
		sourceRe:        phpSourceExprRe,
		sanitizerRe:     phpSanitizerRe,
		loadSinks:       loadPHPStoredStateSinks,
		sinkNeutralises: phpSinkLineSanitizerNeutralises,
		commentPrefixes: []string{"//", "#", "*"},
	}

	// Kotlin — `this.field = <source>`. Kotlin method nodes are named
	// `Type.method` (builder_kotlin.go), so the dotted classQualifier join
	// works unchanged. Field reads are receiver-qualified `this.field`; bare
	// reads are NOT enabled (a bare token would over-match locals/properties,
	// and Kotlin reads its own properties via `this.` or the property name —
	// keeping it `this.`-only is recall-conservative, never FP). All source /
	// sanitizer / sink nets are the EXISTING Kotlin cross-file regexes and
	// sink catalog (kotlinSourceExprRe / kotlinSanitizerRe / loadKotlinSinkPatterns).
	cfgs[rules.LangKotlin] = storedStateLangConfig{
		lang:            rules.LangKotlin,
		fieldWriteRe:    reJavaCSharpFieldWrite,
		readPrefixes:    []string{"this."},
		sourceRe:        kotlinSourceExprRe,
		sanitizerRe:     kotlinSanitizerRe,
		loadSinks:       loadKotlinStoredStateSinks,
		sinkNeutralises: kotlinSinkLineSanitizerNeutralises,
		commentPrefixes: []string{"//", "*"},
	}

	// Swift — `self.field = <source>`. Swift instance properties are read and
	// written via `self.` (no bare-field idiom inside methods). Swift method
	// nodes are `Type.method` (builder_swift.go) → dotted classQualifier join.
	cfgs[rules.LangSwift] = storedStateLangConfig{
		lang:            rules.LangSwift,
		fieldWriteRe:    reSwiftFieldWrite,
		readPrefixes:    []string{"self."},
		sourceRe:        swiftSourceExprRe,
		sanitizerRe:     swiftSanitizerRe,
		loadSinks:       loadSwiftStoredStateSinks,
		sinkNeutralises: swiftSinkLineSanitizerNeutralises,
		commentPrefixes: []string{"//", "*"},
	}

	// Rust is intentionally NOT registered here: builder_rust.go emits impl
	// methods with their BARE name (`load`, `run`) rather than `Type.method`
	// (see its header comment — DetectScopes names impl methods unqualified),
	// so classQualifier() returns "" for every Rust method and the cross-file
	// class-identity join can never form. The producer/source/sink machinery
	// works (verified), but the join key is structurally absent. Wiring Rust
	// needs the impl-type qualifier in the builder first; deferred.

	// Groovy — `this.field = <source>`. Groovy method nodes are `Class.method`
	// (builder_groovy.go) → dotted classQualifier join. Reads are
	// receiver-qualified `this.field`; bare reads are NOT enabled (Groovy does
	// read its own fields bare, but a bare token over-matches locals, so the
	// `this.`-only read keeps FP at zero at the cost of bare-read recall —
	// consistent with Kotlin/Swift here).
	cfgs[rules.LangGroovy] = storedStateLangConfig{
		lang:            rules.LangGroovy,
		fieldWriteRe:    reJavaCSharpFieldWrite,
		readPrefixes:    []string{"this."},
		sourceRe:        groovySourceExprRe,
		sanitizerRe:     groovySanitizerRe,
		loadSinks:       loadGroovyStoredStateSinks,
		sinkNeutralises: groovySinkLineSanitizerNeutralises,
		commentPrefixes: []string{"//", "*", "#"},
	}

	return cfgs
}

// reSwiftFieldWrite matches `self.<field> = <rhs>` for Swift. A plain field
// only (no subscript / nested attribute on the LHS) is captured so the key is
// a stable single field. `==` is excluded by requiring the `=` not be followed
// by `=`.
var reSwiftFieldWrite = regexp.MustCompile(
	`^\s*self\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^=].*)$`)

// loadKotlinStoredStateSinks adapts the cached Kotlin sink patterns into the
// neutral stored-state shape. The kotlinSinkPattern struct carries no
// module/requireModule fields, so those stay zero-valued (as for Ruby/PHP).
func loadKotlinStoredStateSinks() []storedStateSinkPattern {
	src := loadKotlinSinkPatterns()
	out := make([]storedStateSinkPattern, 0, len(src))
	for _, s := range src {
		out = append(out, storedStateSinkPattern{
			pattern:  s.pattern,
			category: s.category,
			method:   s.method,
		})
	}
	return out
}

// loadSwiftStoredStateSinks adapts the cached Swift sink patterns.
func loadSwiftStoredStateSinks() []storedStateSinkPattern {
	src := loadSwiftSinkPatterns()
	out := make([]storedStateSinkPattern, 0, len(src))
	for _, s := range src {
		out = append(out, storedStateSinkPattern{
			pattern:  s.pattern,
			category: s.category,
			method:   s.method,
		})
	}
	return out
}

// loadGroovyStoredStateSinks adapts the cached Groovy sink patterns.
func loadGroovyStoredStateSinks() []storedStateSinkPattern {
	src := loadGroovySinkPatterns()
	out := make([]storedStateSinkPattern, 0, len(src))
	for _, s := range src {
		out = append(out, storedStateSinkPattern{
			pattern:  s.pattern,
			category: s.category,
			method:   s.method,
		})
	}
	return out
}

// rePHPFieldWrite matches `$this-><field> = <rhs>` for PHP. The field name
// carries NO `$` sigil (PHP property access is `$this->prop`, not
// `$this->$prop`). A plain field only (no `[...]` subscript / chained `->` on
// the LHS) is captured so the key is a stable single field; `==`/`=>` are
// excluded by requiring the `=` not be followed by `=` or `>`.
var rePHPFieldWrite = regexp.MustCompile(
	`^\s*\$this->([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^=>].*)$`)

// loadPHPStoredStateSinks adapts the cached PHP sink patterns into the neutral
// stored-state shape. The phpSinkPattern struct carries no module/requireModule
// fields (PHP sink matching is method-name based), so those stay zero-valued.
func loadPHPStoredStateSinks() []storedStateSinkPattern {
	src := loadPHPSinkPatterns()
	out := make([]storedStateSinkPattern, 0, len(src))
	for _, s := range src {
		out = append(out, storedStateSinkPattern{
			pattern:  s.pattern,
			category: s.category,
			method:   s.method,
		})
	}
	return out
}

// reJavaCSharpFieldWrite matches `this.<field> = <rhs>` for Java and C#. A
// plain field only (no subscript / nested attribute / `+=` on the LHS) is
// captured so the key is a stable single field. `==` is excluded by requiring
// the `=` not be followed by `=`.
var reJavaCSharpFieldWrite = regexp.MustCompile(
	`^\s*(?:this\.)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^=].*)$`)

// reJSFieldWrite matches `this.<field> = <rhs>` for JavaScript / TypeScript.
// `$`-prefixed identifiers are permitted on the field name (valid JS idents).
var reJSFieldWrite = regexp.MustCompile(
	`^\s*(?:this\.)([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([^=].*)$`)

// reRubyFieldWrite matches `@<field> = <rhs>` for Ruby instance variables.
var reRubyFieldWrite = regexp.MustCompile(
	`^\s*@([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^=].*)$`)

// --- Source / sanitizer regexes that did not previously exist in the graph
// package. JavaScript, Ruby, and C# already define theirs in their
// crossfile_walk_*.go files; only Java needs new ones (it has no
// crossfile_walk_java.go). These mirror the conservative, two-sided-gated
// style of the existing per-language nets and are distilled from
// java_sources.go / java_sanitizers.go. ---

// javaSourceExprRe matches the canonical Java external request-source shapes
// in a single line. Conservative: servlet / Spring request accessors plus the
// environment / CLI ambient sources. The two-sided source→sink gate suppresses
// standalone matches, so a loose net here is safe.
var javaSourceExprRe = regexp.MustCompile(
	`\b(?:request|req|httpRequest|httpServletRequest)\.(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getQueryString|getCookies|getInputStream|getReader|getPathInfo|getRequestURI|getRequestURL|getQueryParameter)\s*\(` +
		`|\bgetParameter\s*\(` +
		`|@RequestParam\b|@PathVariable\b|@RequestHeader\b|@RequestBody\b|@CookieValue\b` +
		`|\bServletRequest\b.*\.getParameter` +
		`|\bSystem\.getenv\s*\(` +
		`|\bSystem\.getProperty\s*\(`,
)

// javaSanitizerRe matches the common Java sanitizer-call shapes. Distilled
// from java_sanitizers.go: OWASP ESAPI / encoder families, HTML escaping,
// integer coercion, and parameterised-statement builders. Kept narrow so it
// does not swallow the canonical-fix path before the sink fires.
var javaSanitizerRe = regexp.MustCompile(
	`\b(?:` +
		`ESAPI\.encoder` +
		`|Encode\.for(?:Html|HtmlAttribute|JavaScript|Java|Css|Url|UriComponent|Ldap|Sql)` +
		`|StringEscapeUtils\.escape(?:Html\d?|Xml\d?|EcmaScript|Java)` +
		`|HtmlUtils\.htmlEscape` +
		`|URLEncoder\.encode` +
		`|Jsoup\.clean` +
		`|PreparedStatement` +
		`|setParameter\b` +
		`|Integer\.parseInt|Long\.parseLong|Double\.parseDouble` +
		`|Pattern\.quote` +
		`|FilenameUtils\.getName` +
		`|escapeHtml` +
		`|sanitize` +
		`)\s*[\(\.]`,
)

// javaSinkLineSanitizerNeutralises mirrors the Python sinkLineSanitizerNeutralises
// contract for the categories where a wrap-style sanitizer on the same line
// makes the downstream call unambiguously safe.
func javaSinkLineSanitizerNeutralises(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkTemplate, taint.SnkTrustBoundary:
		return true
	}
	return false
}

// loadJavaStoredStateSinks adapts the Java sink catalog into the neutral
// stored-state sink shape.
func loadJavaStoredStateSinks() []storedStateSinkPattern {
	return compileStoredStateSinks(rules.LangJava)
}

// loadCSharpStoredStateSinks compiles the C# sink catalog into the neutral
// shape. The csharpSinkPattern struct doesn't carry module/requireModule, so
// we compile directly from the catalog (ObjectType → module) like Java.
func loadCSharpStoredStateSinks() []storedStateSinkPattern {
	return compileStoredStateSinks(rules.LangCSharp)
}

// loadJavaScriptStoredStateSinks adapts the cached JS sink patterns.
func loadJavaScriptStoredStateSinks() []storedStateSinkPattern {
	src := loadJavaScriptSinkPatterns()
	out := make([]storedStateSinkPattern, 0, len(src))
	for _, s := range src {
		out = append(out, storedStateSinkPattern{
			pattern:       s.pattern,
			category:      s.category,
			method:        s.method,
			module:        s.module,
			requireModule: s.requireModule,
		})
	}
	return out
}

// loadRubyStoredStateSinks adapts the cached Ruby sink patterns.
func loadRubyStoredStateSinks() []storedStateSinkPattern {
	src := loadRubySinkPatterns()
	out := make([]storedStateSinkPattern, 0, len(src))
	for _, s := range src {
		out = append(out, storedStateSinkPattern{
			pattern:       s.pattern,
			category:      s.category,
			method:        s.method,
			module:        s.module,
			requireModule: s.requireModule,
		})
	}
	return out
}

// compileStoredStateSinks compiles a language's sink catalog directly into the
// neutral shape. Used for languages (Java) that don't already have a
// per-language sink-pattern loader in the graph package.
func compileStoredStateSinks(lang rules.Language) []storedStateSinkPattern {
	sinks := taint.SinksForLanguage(lang)
	out := make([]storedStateSinkPattern, 0, len(sinks))
	for _, s := range sinks {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, storedStateSinkPattern{
			pattern:       re,
			category:      s.Category,
			method:        s.MethodName,
			module:        s.ObjectType,
			requireModule: false,
		})
	}
	return out
}

// scanBodyForStoredFieldWrites is the generic (non-Python) producer scan. It
// finds instance-field writes of an external catalog source inside a method
// body, splitting on newlines (the non-Python languages here don't use
// implicit line continuation). body is the method source; startLine is its
// 1-based file-absolute first line. Returns one record per distinct field
// tainted (first tainted writer per field wins).
func scanBodyForStoredFieldWrites(cfg storedStateLangConfig, body string, startLine int) []TaintedFieldWrite {
	if body == "" {
		return nil
	}
	lines := strings.Split(body, "\n")
	seen := map[string]bool{}
	var out []TaintedFieldWrite
	for i, line := range lines {
		if isStoredStateComment(line, cfg.commentPrefixes) {
			continue
		}
		m := cfg.fieldWriteRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		field, rhs := m[1], strings.TrimSpace(m[2])
		if seen[field] {
			continue
		}
		// The RHS must be a genuine external catalog source — not a bare
		// parameter or local. A field set from a method parameter (the
		// caller's value, modelled by param→return) never matches sourceRe,
		// so param-sourced writes drop out for free.
		if !cfg.sourceRe.MatchString(rhs) {
			continue
		}
		// A sanitized write is not a stored external source.
		if cfg.sanitizerRe.MatchString(rhs) {
			continue
		}
		// An ORM/entity lookup keyed by the source stores a DB object /
		// constructed wrapper, not the raw external value
		// (`@user = User.find_by(id: params[:id])`).
		if storedRHSIsEntityLookup(rhs, cfg.sourceRe) {
			continue
		}
		// A type-coerced value cannot carry a payload
		// (`@month = params[:month].to_i`).
		if cfg.coercionRe != nil && cfg.coercionRe.MatchString(rhs) {
			continue
		}
		seen[field] = true
		out = append(out, TaintedFieldWrite{
			Field:          field,
			SourceCategory: taint.SrcExternal,
			Line:           startLine + i,
			SourceText:     truncateExpr(rhs),
		})
	}
	return out
}

// isStoredStateComment reports whether the trimmed line begins with any of the
// language's comment markers.
func isStoredStateComment(line string, prefixes []string) bool {
	trimmed := strings.TrimSpace(line)
	for _, p := range prefixes {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

// fieldTokenReadPrefixes reports whether line reads the instance field via any
// of the language's receiver prefixes as a whole token (so `this.q` does not
// match `this.query`, and `@q` does not match `@query`). For Java/C# a bare
// `field` token is also accepted when bareOK is set — a method reading its own
// instance field unqualified is idiomatic. The bare check still requires a
// token boundary on both sides.
func fieldTokenReadPrefixes(line, field string, prefixes []string, bareOK bool) bool {
	for _, recv := range prefixes {
		if tokenReadWithPrefix(line, recv, field) {
			return true
		}
	}
	if bareOK && bareFieldTokenRead(line, field) {
		return true
	}
	return false
}

// tokenReadWithPrefix reports whether `<recv><field>` appears in line with the
// field terminated by a non-identifier byte (so `this.q` does not match
// `this.query`).
func tokenReadWithPrefix(line, recv, field string) bool {
	needle := recv + field
	from := 0
	for {
		idx := strings.Index(line[from:], needle)
		if idx < 0 {
			return false
		}
		abs := from + idx
		end := abs + len(needle)
		if end >= len(line) || !isIdentChar(line[end]) {
			return true
		}
		from = abs + len(recv)
	}
}

// bareFieldTokenRead reports whether `field` appears as a standalone identifier
// token in line (boundaries on both sides), used for the unqualified Java/C#
// instance-field read. A leading `.` (member access of something else, e.g.
// `obj.field`) disqualifies the match so a same-named property of an unrelated
// object isn't mistaken for the class field.
func bareFieldTokenRead(line, field string) bool {
	from := 0
	for {
		idx := strings.Index(line[from:], field)
		if idx < 0 {
			return false
		}
		abs := from + idx
		end := abs + len(field)
		leftOK := abs == 0 || (!isIdentChar(line[abs-1]) && line[abs-1] != '.')
		rightOK := end >= len(line) || !isIdentChar(line[end])
		if leftOK && rightOK {
			return true
		}
		from = abs + len(field)
		if from >= len(line) {
			return false
		}
	}
}
