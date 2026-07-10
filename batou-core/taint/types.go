// Package taint implements Scope-Aware Taint Tracking (SATT) for Batou.
//
// Unlike regex-based scanning, taint analysis tracks how data flows from
// untrusted sources (user input, network, files) through variable assignments
// and operations to dangerous sinks (SQL queries, command execution, etc.).
//
// The novel aspect: this is designed for generation-time analysis. When AI
// writes code, it typically produces complete functions/scopes. SATT analyzes
// each scope independently, building assignment chains and finding paths
// from sources to sinks that bypass sanitizers.
//
// Architecture:
//
//	Source (user input) → Variable → Operation → ... → Sink (SQL query)
//	                         ↓
//	                    Sanitizer? → breaks taint chain
//
// The engine works for any language through configurable catalogs that
// define sources, sinks, and sanitizers per language.
package taint

import (
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// SourceCategory classifies where untrusted data enters the program.
type SourceCategory string

const (
	SrcUserInput    SourceCategory = "user_input"   // HTTP params, form data, URL query
	SrcNetwork      SourceCategory = "network"      // Network reads, socket data
	SrcFileRead     SourceCategory = "file_read"    // File contents
	SrcEnvVar       SourceCategory = "env_var"      // Environment variables
	SrcDatabase     SourceCategory = "database"     // Database query results
	SrcDeserialized SourceCategory = "deserialized" // Deserialized data
	SrcCLIArg       SourceCategory = "cli_arg"      // Command-line arguments
	SrcExternal     SourceCategory = "external"     // Any external/untrusted source
	// SrcClientStorage is same-origin, client-persisted browser app state
	// (window.localStorage / window.sessionStorage). Like env_var and cli_arg
	// it is NOT attacker-supplied request input — it is data the app itself
	// wrote in a prior same-origin session. It remains a legitimate second-order
	// (persisted-XSS / stored-trust-boundary) source, so it still seeds taint
	// flows and emits as a HINT, but it is deliberately excluded from
	// genuineExternalSourceCategories in scanner/confidence.go so it never
	// confers block-eligibility.
	SrcClientStorage SourceCategory = "client_storage" // localStorage/sessionStorage reads
)

// SinkCategory classifies what dangerous operation consumes the data.
type SinkCategory string

const (
	SnkSQLQuery      SinkCategory = "sql_query"           // SQL queries
	SnkNoSQL         SinkCategory = "nosql_query"         // NoSQL queries (Mongo $where, Firestore, CouchDB views) — CWE-943
	SnkCSV           SinkCategory = "csv_output"          // CSV/spreadsheet formula injection — CWE-1236
	SnkUpload        SinkCategory = "file_upload"         // Unrestricted file upload — CWE-434
	SnkCommand       SinkCategory = "command_exec"        // OS command execution
	SnkFileWrite     SinkCategory = "file_write"          // File path/write operations
	SnkFileRead      SinkCategory = "file_read"           // File read operations (path traversal)
	SnkHTMLOutput    SinkCategory = "html_output"         // HTML response/render (XSS)
	SnkEval          SinkCategory = "code_eval"           // Dynamic code evaluation
	SnkRedirect      SinkCategory = "redirect"            // URL redirect
	SnkLDAP          SinkCategory = "ldap_query"          // LDAP queries
	SnkXPath         SinkCategory = "xpath_query"         // XPath queries
	SnkHeader        SinkCategory = "http_header"         // HTTP response headers
	SnkTemplate      SinkCategory = "template_render"     // Template rendering
	SnkDeserialize   SinkCategory = "deserialize"         // Deserialization input
	SnkLog           SinkCategory = "log_output"          // Logging (log injection)
	SnkCrypto        SinkCategory = "crypto_input"        // Cryptographic operations
	SnkURLFetch      SinkCategory = "url_fetch"           // URL fetching (SSRF)
	SnkTrustBoundary SinkCategory = "trust_boundary"      // Trust boundary violation (CWE-501)
	SnkRegexDoS      SinkCategory = "regex_dos"           // Regex execution on untrusted pattern (CWE-1333 / CWE-400)
	SnkPrototype     SinkCategory = "prototype_pollution" // Prototype pollution via deep merge / path-set (CWE-1321)
	SnkMemory        SinkCategory = "memory_write"        // Unbounded memory copy/write — buffer overflow (CWE-120 / CWE-787)
	SnkNetwork       SinkCategory = "network_write"       // Raw socket/fd write of tainted data — cleartext transmission (CWE-319)
)

// AllSinkCategories enumerates every SinkCategory for iteration.
var AllSinkCategories = []SinkCategory{
	SnkSQLQuery, SnkNoSQL, SnkCSV, SnkUpload, SnkCommand, SnkFileWrite, SnkFileRead, SnkHTMLOutput,
	SnkEval, SnkRedirect, SnkLDAP, SnkXPath, SnkHeader, SnkTemplate,
	SnkDeserialize, SnkLog, SnkCrypto, SnkURLFetch, SnkTrustBoundary, SnkRegexDoS,
	SnkPrototype, SnkMemory, SnkNetwork,
}

// SourceDef defines a pattern that introduces untrusted data.
type SourceDef struct {
	ID          string         // Unique ID, e.g., "go.http.request.formvalue"
	Category    SourceCategory // Classification
	Language    rules.Language // Which language
	Pattern     string         // Regex pattern that matches the source expression
	ObjectType  string         // The receiver type, e.g., "http.Request", "*http.Request"
	MethodName  string         // The method/function name, e.g., "FormValue"
	Description string         // Human description
	Assigns     string         // What gets tainted: "return" (return value) or "arg:N" (Nth argument)

	// WritesArg lists the positional arguments (0-indexed against the
	// source-level argument list, receiver excluded) whose pointee the
	// call mutates with untrusted data. Bind-style methods such as
	// gin's c.ShouldBindXML(&out) or fiber's c.QueryParser(&out) do not
	// return their tainted payload — they decode the request into
	// *out — so consumers must mark the dereferenced pointer as
	// tainted at the call site. Empty (the default) means the call only
	// taints its return value (the existing Assigns behaviour).
	//
	// The field is honoured today by the SSA taint engine
	// (taint/ssaflow). The regex/AST engines treat the call as a normal
	// source whose return is tainted and ignore WritesArg, which is the
	// correct fallback because they cannot track pointee writes.
	WritesArg []int
}

// ArgShape classifies the structural shape a sink argument must (or must not)
// have for the sink to fire. It backs SinkDef.RequiresArgShape — an optional,
// default-zero, POST-MATCH precision gate (see SinkDef.RequiresArgShape).
type ArgShape int

const (
	// ArgShapeAny is the default (zero value): no argument-shape constraint.
	// Behaviour is byte-identical to a sink that never set RequiresArgShape.
	ArgShapeAny ArgShape = iota
	// ArgShapeScalarLiteral requires the argument to be a scalar literal
	// (reserved for future use; not yet consumed by the matcher).
	ArgShapeScalarLiteral
	// ArgShapeContainer requires the argument to be (or resolve to) a
	// container/collection literal — e.g. a PHP array `[...]`, the canonical
	// shape of a MongoDB query-filter document. A provably-scalar argument
	// (scalar literal, primary-key variable, property/element access) drops
	// the candidate; an opaque/unprovable argument is kept.
	ArgShapeContainer
	// ArgShapeStringInterp requires an interpolated/concatenated string
	// argument (reserved for future use; not yet consumed by the matcher).
	ArgShapeStringInterp
)

// PayloadPosition selects WHICH part of a matched sink call carries the
// dangerous (attacker-controllable) payload. It backs SinkDef.PayloadPosition —
// an optional, default-zero, POST-MATCH repositioning of the walker's fire path
// (see SinkDef.PayloadPosition). It NEVER affects Phase-A matching
// (matchSinkCall / matchesCatalogEntry / receiver matching); it only chooses
// which already-matched node the engine inspects for taint before firing.
type PayloadPosition int

const (
	// PayloadDefault (zero value) is today's exact behavior: fire when a
	// positional DangerousArgs node is tainted, with a fallback that fires when
	// the receiver is tainted (unless skipReceiverPayloadFallback disables it).
	// Byte-identical to a sink that never set PayloadPosition.
	PayloadDefault PayloadPosition = iota
	// PayloadReceiver fires ONLY when the RECEIVER (the object the method is
	// called on) is tainted; the dangerous-argument loop is skipped entirely.
	// This is the correct shape for sinks whose attacker-controlled payload is
	// the receiver itself, e.g. Python `template.format_map(values)` /
	// `string.Template(template).substitute(values)`: the DANGER is a tainted
	// TEMPLATE (the receiver), while the mapping argument holds substituted
	// VALUES that are safe under a constant template.
	PayloadReceiver
	// PayloadArgOnly fires ONLY on the DangerousArgs node(s); the receiver-taint
	// fallback is force-skipped. This is the declarative equivalent of the
	// hand-enumerated skipReceiverPayloadFallback set, for argument-payload sinks
	// whose receiver may carry incidental (non-payload) taint.
	PayloadArgOnly
)

// SinkDef defines a pattern where tainted data becomes dangerous.
type SinkDef struct {
	ID            string         // Unique ID, e.g., "go.database.sql.query"
	Category      SinkCategory   // Classification
	Language      rules.Language // Which language
	Pattern       string         // Regex pattern that matches the sink call
	ObjectType    string         // Receiver type
	MethodName    string         // Method/function name
	DangerousArgs []int          // Which arguments are dangerous (0-indexed, -1 = any)
	Severity      rules.Severity // How severe if tainted data reaches this sink

	// Module / RequireModule add an optional binding constraint that the
	// matched call's receiver/package must resolve to a specific module —
	// used to prevent bare-name collisions (e.g. `pickle.loads` vs
	// `json.loads`, `subprocess.run` vs `nox.Session.run`, `os.exec.Command`
	// vs `exec.Command` from a non-os/exec package). When RequireModule is
	// false (the default) the existing matching behaviour is preserved.
	//
	// Module is the bare last component of the import path or the package
	// alias as written in source (e.g. "subprocess", "pickle", "exec",
	// "yaml"). For Go, astflow's TypeEnv resolves the alias via
	// ResolveImport(); the module matches when the call's package alias
	// equals Module OR the resolved import path's last component equals
	// Module. For tree-sitter languages, the receiver name is compared
	// case-insensitively against Module.
	Module        string
	RequireModule bool

	// RequiresArgShape adds an optional POST-MATCH argument-shape gate that
	// only ever SUPPRESSES a fire — never loosens structural matching. It is
	// the sound discriminator for bare-keyed sinks whose dangerous-form vs
	// safe-form differ only by the SHAPE of an argument, not the receiver.
	//
	// The canonical case is PHP's `->find(...)` collision: MongoDB's
	// `$collection->find(['$where' => $tainted])` takes a CONTAINER (array)
	// filter (CWE-943 NoSQL injection), while Laravel Eloquent's
	// `$repo->find($id)` / `Model::find($id)` takes a SCALAR primary key that
	// Eloquent parameterizes (safe). PHP receiver-type discrimination is
	// unavailable, but the arg shape distinguishes them precisely.
	//
	// Default zero value (ArgShapeAny) is a NO-OP — every existing sink keeps
	// its exact behavior, mirroring the Module/RequireModule opt-in precedent.
	// When set to a concrete shape, tsflow's argShapeGateOK inspects the
	// relevant DangerousArgs argument and drops the candidate ONLY when the
	// arg is unambiguously the WRONG shape; an opaque/unprovable arg is kept
	// (recall-preserving). Implemented today for ArgShapeContainer (PHP).
	RequiresArgShape ArgShape

	// PayloadPosition repositions WHICH node of a matched sink call the walker
	// inspects for taint before firing — the receiver, the DangerousArgs, or
	// the default (args with a receiver fallback). It is a POST-MATCH fire-path
	// selector: it runs only AFTER the structural method/receiver match and
	// never loosens matching. The default zero value (PayloadDefault) is a
	// NO-OP, byte-identical to a sink that never set it, mirroring the
	// Module/RequireModule and RequiresArgShape opt-in precedents.
	//
	// The canonical case is Python format-string injection (CWE-1336): for
	// `template.format_map(values)` / `string.Template(tpl).substitute(values)`
	// the attacker-controlled payload is the tainted TEMPLATE (the receiver),
	// not the mapping argument (which holds substituted values, safe under a
	// constant template). PayloadReceiver fires on the tainted receiver and
	// suppresses the const-template + tainted-mapping false positive.
	PayloadPosition PayloadPosition

	// RejectConstrainedName adds an optional POST-MATCH suppressor for
	// reflective sinks whose dangerous payload is an attribute/method NAME
	// (Python getattr/setattr — CWE-470/CWE-915). Such a sink is dangerous only
	// when the NAME is an OPEN attacker-controlled value; it must NOT fire on
	// the two pervasive SAFE framework idioms whose name is drawn from a BOUNDED
	// domain:
	//   - HTTP-verb dispatch: getattr(self, request.method.lower()) — the name
	//     traces to request.method, whose value set is the fixed HTTP-verb list.
	//   - model-metadata iteration: getattr(obj, field.name) — the name is a
	//     schema-bounded model field/column name.
	// plus a string-literal name or a key drawn from a literal dispatch table.
	//
	// When set, tsflow's fire path consults nameArgIsFrameworkConstrained on the
	// DangerousArgs name node and DROPS the fire when the name is provably
	// constrained. The recogniser is conservative-default: anything it cannot
	// prove bounded is treated as NOT constrained (the sink still fires), so
	// genuine attacker-controlled names (getattr(obj, request.args['x'])) are
	// recall-preserved. Default zero value (false) is a NO-OP — byte-identical
	// for every sink that does not opt in, mirroring the Module/RequireModule,
	// RequiresArgShape and PayloadPosition opt-in precedents.
	RejectConstrainedName bool

	Description   string // Human description
	CWEID         string // Associated CWE
	OWASPCategory string // Associated OWASP category

	// Advisory, when non-empty, marks this sink as a KNOWN-VULNERABLE
	// library function: a high-profile API tied to a published security
	// advisory (CVE / GHSA) whose mere reachability from untrusted data is
	// the actionable finding (dependency dataflow-reachability).
	// The value is a short citation, e.g.
	//   "CVE-2021-44228 (Log4Shell) — JNDI lookup expansion in log messages"
	// When set, TaintFlow.ToFinding() re-labels the finding as the
	// BATOU-DEPVULN-<category> family, cites the advisory in the
	// title/description, and tags it "known-vuln" + the advisory ID — WHILE
	// keeping the "taint-analysis" tag so the finding stays TierTaint and is
	// deduplicated by (line, CWE) against any plain deserialize/eval sink on
	// the same line (no double-firing). Attaching Advisory to an EXISTING
	// sink enriches that sink's single finding rather than adding a second
	// one. AdvisoryID is the bare advisory identifier(s) (e.g.
	// "CVE-2021-44228") surfaced as a structured field for downstream triage.
	Advisory   string
	AdvisoryID string
}

// SanitizerDef defines a pattern that neutralizes tainted data.
type SanitizerDef struct {
	ID          string         // Unique ID
	Language    rules.Language // Which language
	Pattern     string         // Regex pattern
	ObjectType  string         // Receiver type
	MethodName  string         // Method/function name
	Neutralizes []SinkCategory // Which sink categories this sanitizes against
	Description string         // Human description
}

// TaintVar represents a variable being tracked through the code.
type TaintVar struct {
	Name       string                // Variable name
	Line       int                   // Line where it was last assigned
	Column     int                   // Column
	Source     *SourceDef            // Origin source (nil = not tainted)
	SourceLine int                   // Line where taint was introduced
	Sanitized  map[SinkCategory]bool // Which sink categories it's sanitized for
	Derived    bool                  // True if taint was derived (e.g., x = tainted_var + "foo")
	Confidence float64               // 0.0 - 1.0, how sure we are this is tainted
}

// IsTaintedFor returns true if this variable is tainted and NOT sanitized
// for the given sink category.
func (tv *TaintVar) IsTaintedFor(cat SinkCategory) bool {
	if tv.Source == nil {
		return false
	}
	if tv.Sanitized != nil && tv.Sanitized[cat] {
		return false
	}
	return true
}

// TaintFlow represents a complete path from source to sink.
type TaintFlow struct {
	Source     SourceDef  // Where the untrusted data entered
	Sink       SinkDef    // Where the data was consumed dangerously
	SourceLine int        // Line of the source
	SinkLine   int        // Line of the sink
	Steps      []FlowStep // Intermediate steps in the flow
	FilePath   string     // File being analyzed
	ScopeName  string     // Function/method scope
	Confidence float64    // Overall flow confidence
}

// FlowStep represents one step in a taint flow path.
type FlowStep struct {
	Line        int    // Line number
	Description string // What happens here, e.g., "assigned to variable 'query'"
	VarName     string // Variable involved
}

// ToFinding converts a TaintFlow into a rules.Finding for Batou reporting.
func (tf *TaintFlow) ToFinding() rules.Finding {
	title := "Tainted data flows from " + string(tf.Source.Category) + " to " + string(tf.Sink.Category)

	desc := "Untrusted data from " + tf.Source.Description +
		" flows to " + tf.Sink.Description + " without proper sanitization."

	suggestion := "Sanitize or validate the data before passing it to " + tf.Sink.MethodName + "."

	// Build matched text showing the flow
	matched := tf.Source.MethodName + " (line " +
		itoa(tf.SourceLine) + ") → "
	for _, step := range tf.Steps {
		matched += step.VarName + " → "
	}
	matched += tf.Sink.MethodName + " (line " + itoa(tf.SinkLine) + ")"

	conf := "high"
	if tf.Confidence < 0.7 {
		conf = "medium"
	}
	if tf.Confidence < 0.4 {
		conf = "low"
	}

	ruleID := "BATOU-TAINT-" + string(tf.Sink.Category)
	tags := []string{"taint-analysis", "dataflow", string(tf.Source.Category), string(tf.Sink.Category)}
	advisory := tf.Sink.Advisory

	// Dependency dataflow-reachability. When the sink is a known
	// vulnerable library function (Advisory set), this flow is the actionable
	// "you actually CALL the vulnerable function WITH attacker-controlled
	// input" finding. Re-label it BATOU-DEPVULN-<category> and cite the
	// advisory. We KEEP the "taint-analysis" tag so the finding stays
	// TierTaint and dedup (by line+CWE in scanner/dedup.go) collapses it with
	// any plain deserialize/eval sink on the same line — exactly one finding
	// is emitted, and the DEPVULN winner carries the advisory.
	if advisory != "" {
		ruleID = "BATOU-DEPVULN-" + string(tf.Sink.Category)
		title = "Untrusted data reaches known-vulnerable " + tf.Sink.MethodName +
			" (" + advisory + ")"
		desc = "Untrusted data from " + tf.Source.Description +
			" flows to " + tf.Sink.MethodName +
			", a library function with a published security advisory (" + advisory +
			"). Reaching this function with attacker-controlled input is directly exploitable. " + desc
		tags = append(tags, "known-vuln", "dependency-vuln")
		if tf.Sink.AdvisoryID != "" {
			tags = append(tags, tf.Sink.AdvisoryID)
		}
	}

	return rules.Finding{
		RuleID:          ruleID,
		Severity:        tf.Sink.Severity,
		SeverityLabel:   tf.Sink.Severity.String(),
		Title:           title,
		Description:     desc,
		FilePath:        tf.FilePath,
		LineNumber:      tf.SinkLine,
		MatchedText:     matched,
		TaintPath:       tf.taintPath(),
		SourceCategory:  string(tf.Source.Category),
		SinkCategory:    string(tf.Sink.Category),
		Suggestion:      suggestion,
		CWEID:           tf.Sink.CWEID,
		OWASPCategory:   tf.Sink.OWASPCategory,
		Advisory:        advisory,
		AdvisoryID:      tf.Sink.AdvisoryID,
		Confidence:      conf,
		ConfidenceScore: tf.Confidence,
		Tags:            tags,
	}
}

// taintPath builds the structured source→propagation…→sink path from the
// flow's recorded steps. The intra-procedural path is already captured in
// tf.Steps; this just lifts it onto a rules.Finding as structured data.
// Single-file: every step's File is tf.FilePath.
func (tf *TaintFlow) taintPath() []rules.TaintStep {
	srcLabel := tf.Source.MethodName
	if srcLabel == "" {
		srcLabel = tf.Source.Description
	}
	if srcLabel == "" {
		srcLabel = string(tf.Source.Category)
	}

	path := make([]rules.TaintStep, 0, len(tf.Steps)+2)
	path = append(path, rules.TaintStep{
		File:  tf.FilePath,
		Line:  tf.SourceLine,
		Kind:  rules.TaintStepSource,
		Label: srcLabel,
	})

	for _, st := range tf.Steps {
		// The source step is sometimes also recorded as the first FlowStep
		// (same line, "tainted by …"); skip that duplicate.
		if st.Line == tf.SourceLine && len(path) == 1 {
			continue
		}
		// Every intermediate FlowStep is a propagation step. No taint engine
		// emits a FlowStep that *describes* a bypassed sanitizer — when a real
		// sanitizer is hit the flow is cut, not reported — so a keyword match on
		// the description could only ever mislabel a benign propagation (e.g.
		// through a method named validateAndReturn() or encodeURL()) as
		// "sanitizer-bypassed". The rules.TaintStepSanitizerBypassed constant is
		// kept for forward-compat in case an engine emits it deliberately.
		desc := st.Description
		label := desc
		if label == "" {
			if st.VarName != "" {
				label = "assigned to " + st.VarName
			} else {
				label = "data flows"
			}
		} else if st.VarName != "" && !strings.Contains(label, st.VarName) {
			label = label + " (" + st.VarName + ")"
		}
		path = append(path, rules.TaintStep{
			File:  tf.FilePath,
			Line:  st.Line,
			Kind:  rules.TaintStepPropagation,
			Label: label,
		})
	}

	sinkLabel := tf.Sink.MethodName
	if sinkLabel == "" {
		sinkLabel = tf.Sink.Description
	}
	if sinkLabel == "" {
		sinkLabel = string(tf.Sink.Category)
	}
	path = append(path, rules.TaintStep{
		File:  tf.FilePath,
		Line:  tf.SinkLine,
		Kind:  rules.TaintStepSink,
		Label: sinkLabel,
	})
	return path
}

// Scope represents a code block (function, method, closure) being analyzed.
type Scope struct {
	Name      string   // Function/method name
	StartLine int      // First line of scope
	EndLine   int      // Last line of scope
	Params    []string // Parameter names
	Body      string   // The source code within this scope
	Lines     []string // Lines of the body
	Parent    *Scope   // Enclosing scope (nil for top-level)
}

// LanguageCatalog provides source/sink/sanitizer definitions for a language.
type LanguageCatalog interface {
	Language() rules.Language
	Sources() []SourceDef
	Sinks() []SinkDef
	Sanitizers() []SanitizerDef
}

// itoa is a minimal int-to-string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := [20]byte{}
	i := len(buf) - 1
	for n > 0 {
		buf[i] = byte('0' + n%10)
		i--
		n /= 10
	}
	if neg {
		buf[i] = '-'
		i--
	}
	return string(buf[i+1:])
}
