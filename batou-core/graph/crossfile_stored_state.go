package graph

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/tsflow"
	"github.com/turenlabs/batou-rules/rules"
)

// Cross-file STORED-STATE taint (Tier-1, the #1 missed-flow class).
//
// The call-edge-driven cross-file walk (crossfile_walk*.go) only connects a
// caller and callee that share a call site: it threads param→sink and
// return→sink. The canonical object-oriented vulnerability has NO such call
// edge between the two methods that matter:
//
//	# file A
//	class UserController:
//	    def load(self):
//	        self.q = request.args["q"]     # WRITE external taint into a field
//
//	# file B (a different file)
//	class UserController:
//	    def run(self):
//	        os.system(self.q)              # READ that field -> sink
//
// `load` never calls `run`; they communicate through object identity (the
// shared `self.q` field). The two methods can live in different files (a
// class split across modules, a partial/monkeypatched class, a mixin). Today
// the flow is silently dropped.
//
// This pass closes it WITHOUT whole-program points-to:
//
//   - PRODUCER: every method that writes a genuine external catalog source
//     into `self.<field>` records that field key on its TaintSig
//     (TaintedFields). This mirrors the single-file stored-state channel in
//     tsflow/field_global_state.go, lifted to the cross-file signature.
//   - CONSUMER: every method that READS `self.<field>` into a sink is joined
//     to a producer by ENCLOSING CLASS identity (the dotted qualifier on the
//     FuncNode name — `UserController.load` and `UserController.run` share
//     class `UserController`). The producer may live in a DIFFERENT file, or
//     — for languages tsflow's intra-file stored-state channel does NOT cover
//     (Ruby / PHP / Kotlin / Swift / Groovy) — in a different METHOD of the
//     SAME file. For the tsflow-covered languages (Python / JS / TS / Java /
//     C#) same-file pairs stay excluded so the two channels never
//     double-report one flow; a write+read inside one method is always
//     excluded (plain intra-procedural flow, tsflow territory everywhere).
//
// FP discipline (the join key is a class NAME, which two unrelated classes
// could share across files):
//   - the written value must be a GENUINE external catalog source
//     (pythonSourceExprRe), not a parameter — a field set from `__init__`'s
//     argument is the caller's value, already modelled by param→return;
//   - the read must reach a sink whose dangerous argument literally contains
//     `self.<field>` — a bare same-named field is not enough;
//   - sanitized writes and sanitized sink lines are dropped (shared
//     pythonSanitizerRe / sink-line gates);
//   - confidence is 0.8 (ConfBaseInterproc-equivalent), matching the other
//     cross-file interproc findings, so a name-collision-driven flow is a
//     hint, not a hard block, unless the external-origin block gate also
//     agrees.
//
// Scope: Python only in this slice (the cleanest body-scan + source-regex
// helpers, OWASP-benched so recall is measurable). The TaintSig.TaintedFields
// field and the WalkCrossFileStoredState driver are language-agnostic; other
// languages can register a producer/reader scanner later.

// rePyFieldWrite matches a single-line instance-field assignment whose LHS is
// `self.<field>` (or `cls.<field>`) and captures the field name and RHS. Only
// a plain field (no subscript / nested attribute on the LHS) is captured —
// `self.cache[k] = ...` and `self.a.b = ...` are intentionally excluded
// because they are not stable single-field keys.
var rePyFieldWrite = regexp.MustCompile(`^\s*(?:self|cls)\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$`)

// storedFieldProducer is a (class, field) write fact harvested from one
// method body. Keyed in the side-table by class qualifier.
type storedFieldProducer struct {
	node       *FuncNode
	field      string
	sourceText string
	sourceCat  taint.SourceCategory
	line       int
}

// scanPythonBodyForStoredFieldWrites finds instance-field writes of an
// external catalog source inside a Python method body. body is the method
// source; startLine is its 1-based file-absolute first line. Returns one
// record per distinct field tainted (the first tainted writer per field wins).
func scanPythonBodyForStoredFieldWrites(body string, startLine int) []TaintedFieldWrite {
	if body == "" {
		return nil
	}
	lines, offsets := joinPythonParenContinuations(body)
	seen := map[string]bool{}
	var out []TaintedFieldWrite
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := rePyFieldWrite.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		field, rhs := m[1], strings.TrimSpace(m[2])
		if seen[field] {
			continue
		}
		// The RHS must be a genuine external catalog source — not a bare
		// parameter or local. pythonSourceExprRe is the same coarse net the
		// call-edge walk uses for "is this reachable from untrusted input".
		if !pythonSourceExprRe.MatchString(rhs) {
			continue
		}
		// A sanitized write is not a stored source.
		if pythonSanitizerRe.MatchString(rhs) {
			continue
		}
		// An ORM/entity lookup keyed by the source is not a stored RAW value
		// (`self.user = User.objects.get(pk=request.GET["id"])` stores a DB
		// object, not the attacker string).
		if storedRHSIsEntityLookup(rhs, pythonSourceExprRe) {
			continue
		}
		lineOffset := i
		if i < len(offsets) {
			lineOffset = offsets[i]
		}
		seen[field] = true
		out = append(out, TaintedFieldWrite{
			Field:          field,
			SourceCategory: taint.SrcExternal,
			Line:           startLine + lineOffset,
			SourceText:     truncateExpr(rhs),
		})
	}
	return out
}

// reConstReceiverChain matches an RHS whose expression BEGINS with a
// capitalized-constant receiver chain entering a call — `User.find(`,
// `Jobs::CreateUserReviewable.new(`, `AiTool.includes(`, `\App\User::find(`
// (PHP FQCN), `User.objects.get(`. Lowercase receivers (`params[`,
// `request.getParameter(`, `call.parameters[`) never match.
var reConstReceiverChain = regexp.MustCompile(
	`^\\?(?:[A-Za-z_][A-Za-z0-9_]*\\)*[A-Z][A-Za-z0-9_]*(?:::[A-Z][A-Za-z0-9_]*)*\s*[.(:]`)

// storedRHSIsEntityLookup reports whether the external-source match inside rhs
// sits purely in ARGUMENT position of a capitalized-constant receiver call
// chain — the `@user = User.find_by(id: params[:id])` /
// `self.q = TopicView.new(request.args["id"])` shape. The stored value is
// then an ORM entity / constructed object, NOT the raw external value, so the
// later `sink(@user)` read is not attacker-controlled data reaching the sink.
// A source at position 0 (`params[:q]`, `ENV["X"]`, `System.getenv("X")`) or
// inside string interpolation (`"cmd #{params[:q]}"`) keeps its taint.
func storedRHSIsEntityLookup(rhs string, sourceRe *regexp.Regexp) bool {
	loc := sourceRe.FindStringIndex(rhs)
	if loc == nil || loc[0] == 0 {
		return false
	}
	prefix := rhs[:loc[0]]
	if !reConstReceiverChain.MatchString(prefix) {
		return false
	}
	// The source must be INSIDE an open argument list of that chain — an
	// unbalanced `(` before the match. A balanced prefix means the source
	// stands after the call (`User.table_name + params[:q]`), which stays
	// tainted.
	return strings.Count(prefix, "(") > strings.Count(prefix, ")")
}

// truncateExpr bounds an RHS/source expression used in a taint-path label.
func truncateExpr(s string) string {
	const max = 80
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// ensurePythonStoredFieldProducers populates node.TaintSig.TaintedFields for a
// Python method that writes external taint into an instance field. Idempotent:
// a node whose TaintedFields is already set is left untouched.
func ensurePythonStoredFieldProducers(cg *CallGraph, node *FuncNode) {
	if node == nil || node.Language != rules.LangPython {
		return
	}
	if len(node.TaintSig.TaintedFields) > 0 {
		return
	}
	// Only methods (a dotted class-qualified name) participate — a bare
	// module-level function has no `self` receiver.
	if !strings.Contains(node.Name, ".") {
		return
	}
	content, ok := loadCallerFile(cg, node.FilePath, map[string]string{})
	if !ok {
		return
	}
	body := extractFuncBody(content, node.StartLine, node.EndLine)
	if body == "" {
		return
	}
	writes := scanPythonBodyForStoredFieldWrites(body, node.StartLine)
	if len(writes) > 0 {
		node.TaintSig.TaintedFields = writes
		node.TaintSig.IsPure = false
	}
}

// classQualifier returns the enclosing class portion of a method name.
//
// The dotted convention (`UserController.load` → "UserController"; nested
// `Outer.Inner.m` → "Outer.Inner") covers Java / JS / TS / Ruby / C# / Python.
// PHP encodes its method nodes as `Namespace\Class::method` (a `::` scope
// separator and a `\`-qualified class), so the `::` form is split first when
// present — `App\Repo::find` → "App\Repo". Returns "" for a bare function name
// with no enclosing class.
func classQualifier(name string) string {
	if idx := strings.LastIndex(name, "::"); idx >= 0 {
		return name[:idx]
	}
	idx := strings.LastIndex(name, ".")
	if idx < 0 {
		return ""
	}
	return name[:idx]
}

// WalkCrossFileStoredState is the cross-file stored-state driver. It runs as
// part of the dirscan finalize pass (after signature propagation). For each
// participating language it:
//
//  1. harvests every method's instance-field taint writes into a side-table
//     keyed by (class qualifier, field);
//  2. scans every method body for a sink reading the same field where that
//     (class, field) was written-tainted by a producer in a DIFFERENT file —
//     or, for languages without tsflow's intra-file stored-state channel, a
//     different METHOD of the same file — and emits the stored-state finding.
//
// Python keeps its dedicated producer/reader path (it needs implicit-line-
// continuation joining); Java, JavaScript/TypeScript, Ruby, and C# go through
// the generic per-language config in crossfile_stored_state_langs.go. Returns
// the synthesised findings, deduplicated by (reader file, sink line, field).
func WalkCrossFileStoredState(cg *CallGraph) []rules.Finding {
	if cg == nil {
		return nil
	}

	ids := make([]string, 0, len(cg.Nodes))
	for id := range cg.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var findings []rules.Finding
	findings = append(findings, walkPythonStoredState(cg, ids)...)
	for lang := range storedStateLangConfigs {
		findings = append(findings, walkLangStoredState(cg, ids, storedStateLangConfigs[lang])...)
	}
	return findings
}

// walkPythonStoredState runs the Python slice of the stored-state channel,
// preserving the original #1221 behaviour for instance fields.
//
// Module globals (the IsGlobal branch) are NOT activated here: a Python file
// that holds only top-level globals (the canonical config-module shape) has no
// FuncNode AND no FileScope in the call graph — the graph is built from
// functions/classes, so a function-less producer module is structurally
// invisible at this level. Wiring globals soundly needs the on-disk file
// enumeration that lives in dirscan, not the cg. Deferred as follow-up; see
// crossfile_stored_state header and the task report.
func walkPythonStoredState(cg *CallGraph, ids []string) []rules.Finding {
	// Producer side-table: class qualifier -> field -> producer record.
	// May-analysis: any tainted writer of a field makes it a stored source;
	// the highest (first, by sorted-ID determinism) writer wins.
	producers := map[string]map[string]storedFieldProducer{}
	for _, id := range ids {
		node := cg.Nodes[id]
		if node == nil || node.Language != rules.LangPython {
			continue
		}
		ensurePythonStoredFieldProducers(cg, node)
		if len(node.TaintSig.TaintedFields) == 0 {
			continue
		}
		cls := classQualifier(node.Name)
		if cls == "" {
			continue
		}
		for _, w := range node.TaintSig.TaintedFields {
			if w.IsGlobal {
				continue // module-global channel deferred (see doc above)
			}
			addStoredProducer(producers, cls, w, node)
		}
	}
	if len(producers) == 0 {
		return nil
	}

	sinkPatterns := loadPythonSinkPatterns()
	if len(sinkPatterns) == 0 {
		return nil
	}
	neutral := make([]storedStateSinkPattern, 0, len(sinkPatterns))
	for _, p := range sinkPatterns {
		neutral = append(neutral, storedStateSinkPattern{
			pattern: p.pattern, category: p.category, method: p.method,
			module: p.module, requireModule: p.requireModule,
		})
	}

	pyCfg := storedStateLangConfig{
		lang:            rules.LangPython,
		fieldWriteRe:    rePyFieldWrite,
		readPrefixes:    []string{"self.", "cls."},
		sinkNeutralises: sinkLineSanitizerNeutralises,
		commentPrefixes: []string{"#"},
	}

	var findings []rules.Finding
	seen := map[string]bool{}
	for _, id := range ids {
		reader := cg.Nodes[id]
		if reader == nil || reader.Language != rules.LangPython {
			continue
		}
		cls := classQualifier(reader.Name)
		if cls == "" {
			continue
		}
		fields := producers[cls]
		if len(fields) == 0 {
			continue
		}
		content, ok := loadCallerFile(cg, reader.FilePath, map[string]string{})
		if !ok {
			continue
		}
		body := extractFuncBody(content, reader.StartLine, reader.EndLine)
		if body == "" {
			continue
		}
		lines, offsets := joinPythonParenContinuations(body)
		findings = append(findings,
			scanReaderForStoredSinks(pyCfg, cls, false, reader, lines, offsets, fields, neutral, seen)...,
		)
	}
	return findings
}

// walkLangStoredState runs the generic (non-Python) stored-state channel for
// one language config (Java / JS / TS / Ruby / C#). Instance fields only;
// module-globals are not modelled for these languages in this slice.
func walkLangStoredState(cg *CallGraph, ids []string, cfg storedStateLangConfig) []rules.Finding {
	bareOK := langAllowsBareFieldRead(cfg.lang)

	producers := map[string]map[string]storedFieldProducer{}
	for _, id := range ids {
		node := cg.Nodes[id]
		if node == nil || node.Language != cfg.lang {
			continue
		}
		ensureGenericStoredFieldProducers(cg, cfg, node)
		if len(node.TaintSig.TaintedFields) == 0 {
			continue
		}
		cls := classQualifier(node.Name)
		if cls == "" {
			continue
		}
		for _, w := range node.TaintSig.TaintedFields {
			if w.IsGlobal {
				continue
			}
			addStoredProducer(producers, cls, w, node)
		}
	}
	if len(producers) == 0 {
		return nil
	}

	sinkPatterns := cfg.loadSinks()
	if len(sinkPatterns) == 0 {
		return nil
	}

	var findings []rules.Finding
	seen := map[string]bool{}
	for _, id := range ids {
		reader := cg.Nodes[id]
		if reader == nil || reader.Language != cfg.lang {
			continue
		}
		cls := classQualifier(reader.Name)
		if cls == "" {
			continue
		}
		fields := producers[cls]
		if len(fields) == 0 {
			continue
		}
		content, ok := loadCallerFile(cg, reader.FilePath, map[string]string{})
		if !ok {
			continue
		}
		body := extractFuncBody(content, reader.StartLine, reader.EndLine)
		if body == "" {
			continue
		}
		lines := strings.Split(body, "\n")
		offsets := identityOffsets(len(lines))
		findings = append(findings,
			scanReaderForStoredSinksBare(cfg, cls, false, bareOK, reader, lines, offsets, fields, sinkPatterns, seen)...,
		)
	}
	return findings
}

// langAllowsBareFieldRead reports whether an unqualified `field` token counts
// as an instance-field read in this language. Java and C# read their own
// fields unqualified idiomatically; JS/TS/Ruby always qualify (`this.x` / `@x`).
func langAllowsBareFieldRead(lang rules.Language) bool {
	return lang == rules.LangJava || lang == rules.LangCSharp
}

// addStoredProducer records the first tainted writer of a (key, field) into a
// producer side-table.
func addStoredProducer(table map[string]map[string]storedFieldProducer, key string, w TaintedFieldWrite, node *FuncNode) {
	fields := table[key]
	if fields == nil {
		fields = map[string]storedFieldProducer{}
		table[key] = fields
	}
	if _, exists := fields[w.Field]; exists {
		return
	}
	fields[w.Field] = storedFieldProducer{
		node:       node,
		field:      w.Field,
		sourceText: w.SourceText,
		sourceCat:  w.SourceCategory,
		line:       w.Line,
	}
}

// ensureGenericStoredFieldProducers populates node.TaintSig.TaintedFields for a
// non-Python method that writes external taint into an instance field.
// Idempotent.
func ensureGenericStoredFieldProducers(cg *CallGraph, cfg storedStateLangConfig, node *FuncNode) {
	if node == nil || node.Language != cfg.lang {
		return
	}
	if len(node.TaintSig.TaintedFields) > 0 {
		return
	}
	// Only methods (a class-qualified name) participate. The class join key is
	// the dotted qualifier for most languages and the `Namespace\Class::`
	// scope for PHP, so a node qualifies if either separator is present.
	if !strings.Contains(node.Name, ".") && !strings.Contains(node.Name, "::") {
		return
	}
	content, ok := loadCallerFile(cg, node.FilePath, map[string]string{})
	if !ok {
		return
	}
	body := extractFuncBody(content, node.StartLine, node.EndLine)
	if body == "" {
		return
	}
	writes := scanBodyForStoredFieldWrites(cfg, body, node.StartLine)
	if len(writes) > 0 {
		node.TaintSig.TaintedFields = writes
		node.TaintSig.IsPure = false
	}
}

// identityOffsets returns [0,1,...,n-1] — the no-op offset map for languages
// that split on newlines without continuation joining.
func identityOffsets(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

// scanReaderForStoredSinks scans one reader method body for sinks that consume
// a cross-file stored field (the qualified-prefix-only variant — Python /
// JS / TS / Ruby, where every field read is receiver-qualified).
func scanReaderForStoredSinks(
	cfg storedStateLangConfig,
	joinLabel string,
	isGlobal bool,
	reader *FuncNode,
	lines []string,
	offsets []int,
	fields map[string]storedFieldProducer,
	sinkPatterns []storedStateSinkPattern,
	seen map[string]bool,
) []rules.Finding {
	return scanReaderForStoredSinksBare(cfg, joinLabel, isGlobal, false, reader, lines, offsets, fields, sinkPatterns, seen)
}

// scanReaderForStoredSinksBare is the full reader scan. bareOK enables the
// unqualified instance-field read (Java / C#).
func scanReaderForStoredSinksBare(
	cfg storedStateLangConfig,
	joinLabel string,
	isGlobal bool,
	bareOK bool,
	reader *FuncNode,
	lines []string,
	offsets []int,
	fields map[string]storedFieldProducer,
	sinkPatterns []storedStateSinkPattern,
	seen map[string]bool,
) []rules.Finding {
	var out []rules.Finding
	for i, line := range lines {
		if isStoredStateComment(line, cfg.commentPrefixes) {
			continue
		}
		// Which stored field does this line read? Require a receiver-qualified
		// (or, for Java/C#, bare-token) field read so a same-named local can't
		// satisfy it.
		var hitField string
		var prod storedFieldProducer
		for f, p := range fields {
			// Same-file pairs participate only when tsflow's intra-file
			// stored-state channel does NOT already cover the language
			// (Ruby / PHP / Kotlin / Swift / Groovy) — for the covered
			// languages (Python / JS / TS / Java / C#) the Layer-3 walk
			// surfaces the same flow at higher confidence and finalize-emitted
			// findings are never deduplicated against per-file output, so
			// allowing them here would double-report. A write and read in the
			// SAME method (p.node == reader) is always skipped: that is plain
			// intra-procedural flow, tsflow territory in every language.
			if p.node.FilePath == reader.FilePath {
				if p.node == reader || tsflow.SupportsStoredStateChannel(cfg.lang) {
					continue
				}
			}
			if storedFieldRead(cfg, isGlobal, bareOK, line, f) {
				hitField = f
				prod = p
				break
			}
		}
		if hitField == "" {
			continue
		}
		// A line that WRITES the field is not a read of it: in
		// `@user = User.find(params[:id])` the field token is the assignment
		// target, so a sink pattern elsewhere on the line does not consume the
		// stored value. A write whose RHS also reads the field
		// (`self.q = self.q + ...`) keeps counting as a read.
		if !isGlobal && cfg.fieldWriteRe != nil {
			if m := cfg.fieldWriteRe.FindStringSubmatch(line); m != nil && m[1] == hitField &&
				!storedFieldRead(cfg, isGlobal, bareOK, m[2], hitField) {
				continue
			}
		}
		for _, p := range sinkPatterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			if p.requireModule && p.module != "" && !strings.Contains(line, p.module) {
				continue
			}
			// The sink line must be sanitizer-free for categories the catalog
			// sanitizer neutralises end-to-end.
			if cfg.sanitizerRe != nil && cfg.sanitizerRe.MatchString(line) {
				if cfg.sinkNeutralises != nil && cfg.sinkNeutralises(p.category) {
					continue
				}
			} else if cfg.sanitizerRe == nil && pythonSanitizerRe.MatchString(line) {
				// Python config carries no sanitizerRe field; use the package
				// pythonSanitizerRe (the original #1221 behaviour).
				if cfg.sinkNeutralises != nil && cfg.sinkNeutralises(p.category) {
					continue
				}
			}
			lineOffset := i
			if i < len(offsets) {
				lineOffset = offsets[i]
			}
			sinkLine := reader.StartLine + lineOffset
			key := fmt.Sprintf("%s:%d:%s", reader.FilePath, sinkLine, hitField)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, buildStoredStateFinding(cfg, joinLabel, isGlobal, reader, prod, p, hitField, sinkLine, strings.TrimSpace(line)))
			break
		}
	}
	return out
}

// storedFieldRead reports whether line reads the stored field. For a module
// global the bare name is the read token; for an instance field the
// receiver-qualified prefixes apply (plus the optional bare-token read for
// Java/C#).
func storedFieldRead(cfg storedStateLangConfig, isGlobal, bareOK bool, line, field string) bool {
	if isGlobal {
		return bareFieldTokenRead(line, field)
	}
	return fieldTokenReadPrefixes(line, field, cfg.readPrefixes, bareOK)
}

// receiverLabel returns the syntactic receiver prefix used in finding labels
// for instance-field reads in this language (`self.`, `this.`, `@`).
func receiverLabel(cfg storedStateLangConfig) string {
	if len(cfg.readPrefixes) > 0 {
		return cfg.readPrefixes[0]
	}
	return "self."
}

// buildStoredStateFinding constructs the cross-file stored-state finding with a
// two-step taint path: the producer's field write → the reader's sink.
func buildStoredStateFinding(
	cfg storedStateLangConfig,
	joinLabel string,
	isGlobal bool,
	reader *FuncNode,
	prod storedFieldProducer,
	sink storedStateSinkPattern,
	field string,
	sinkLine int,
	sinkText string,
) rules.Finding {
	sev := severityForSinkCategory[sink.category]
	if sev < rules.High {
		sev = rules.High
	}
	cwe := cweForSinkCategory[sink.category]
	owasp := owaspForSinkCategory[sink.category]

	sinkLabel := sink.method
	if sinkLabel == "" {
		sinkLabel = string(sink.category)
	}

	recv := receiverLabel(cfg)
	fieldRef := recv + field
	stateKind := "instance state"
	joinKind := "class"
	// writerRef names the producer scope in the labels: a method call
	// (`load()`) for instance fields, but a module top-level (no parens) for a
	// function-less module global, where prod.node.Name is the module name.
	writerRef := prod.node.Name + "()"
	if isGlobal {
		fieldRef = field
		stateKind = "module-global state"
		joinKind = "module"
		writerRef = "module " + prod.node.Name
	}

	taintPath := []rules.TaintStep{
		{
			File:  prod.node.FilePath,
			Line:  prod.line,
			Kind:  rules.TaintStepSource,
			Label: fmt.Sprintf("external taint stored in %s by %s (%s)", fieldRef, writerRef, prod.sourceText),
		},
		{
			File:  reader.FilePath,
			Line:  sinkLine,
			Kind:  rules.TaintStepSink,
			Label: fmt.Sprintf("%s read into %s in %s()", fieldRef, sinkLabel, reader.Name),
		},
	}

	sharedClause := fmt.Sprintf("share %s %s", joinKind, joinLabel)
	if isGlobal {
		sharedClause = fmt.Sprintf("are joined by %s %s", joinKind, joinLabel)
	}

	// A same-file pair (two methods of one class in one file, joined because
	// tsflow's intra-file channel doesn't cover the language) renders
	// cross-method wording; the boundary crossed is the method, not the file.
	sameFile := prod.node.FilePath == reader.FilePath
	titleKind := "Cross-file"
	boundaryClause := fmt.Sprintf("%s across files, so the value crosses the file boundary", sharedClause)
	spanTag := "cross-file"
	if sameFile {
		titleKind = "Cross-method"
		boundaryClause = fmt.Sprintf("%s in the same file, so the value crosses the method boundary", sharedClause)
		spanTag = "cross-method"
	}

	return rules.Finding{
		RuleID:        fmt.Sprintf("BATOU-INTERPROC-%s", strings.ToUpper(string(sink.category))),
		Severity:      sev,
		SeverityLabel: sev.String(),
		Title: fmt.Sprintf(
			"%s stored-state taint: %s.%s flows to %s",
			titleKind, joinLabel, field, sink.method,
		),
		Description: fmt.Sprintf(
			"External input stored in %s by %s (%s:%d) is read by %s() (%s:%d) "+
				"and passed to %s without sanitization. The reader and writer %s "+
				"through %s "+
				"rather than a call argument — a stored-state %s vulnerability.",
			fieldRef, writerRef, prod.node.FilePath, prod.line,
			reader.Name, reader.FilePath, sinkLine,
			sink.method, boundaryClause, stateKind, sink.category,
		),
		FilePath:    reader.FilePath,
		LineNumber:  sinkLine,
		MatchedText: sinkText,
		TaintPath:   taintPath,
		Suggestion: fmt.Sprintf(
			"Validate or sanitize %s before passing it to %s(), or sanitize the "+
				"value where it is stored in %s.",
			fieldRef, sink.method, writerRef,
		),
		CWEID:           cwe,
		OWASPCategory:   owasp,
		Confidence:      "high",
		ConfidenceScore: 0.8,
		SourceCategory:  string(taint.SrcExternal),
		SinkCategory:    string(sink.category),
		Language:        cfg.lang,
		Tags: []string{
			"interprocedural", "taint-analysis", spanTag, "stored-state",
			string(cfg.lang), string(sink.category),
		},
	}
}
