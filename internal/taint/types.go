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

import "github.com/turenlabs/batou/internal/rules"

// SourceCategory classifies where untrusted data enters the program.
type SourceCategory string

const (
	SrcUserInput   SourceCategory = "user_input"   // HTTP params, form data, URL query
	SrcNetwork     SourceCategory = "network"       // Network reads, socket data
	SrcFileRead    SourceCategory = "file_read"     // File contents
	SrcEnvVar      SourceCategory = "env_var"       // Environment variables
	SrcDatabase    SourceCategory = "database"       // Database query results
	SrcDeserialized SourceCategory = "deserialized"  // Deserialized data
	SrcCLIArg      SourceCategory = "cli_arg"       // Command-line arguments
	SrcExternal    SourceCategory = "external"       // Any external/untrusted source
)

// SinkCategory classifies what dangerous operation consumes the data.
type SinkCategory string

const (
	SnkSQLQuery    SinkCategory = "sql_query"      // SQL queries
	SnkCommand     SinkCategory = "command_exec"    // OS command execution
	SnkFileWrite   SinkCategory = "file_write"      // File path/write operations
	SnkHTMLOutput  SinkCategory = "html_output"     // HTML response/render (XSS)
	SnkEval        SinkCategory = "code_eval"       // Dynamic code evaluation
	SnkRedirect    SinkCategory = "redirect"        // URL redirect
	SnkLDAP        SinkCategory = "ldap_query"      // LDAP queries
	SnkXPath       SinkCategory = "xpath_query"     // XPath queries
	SnkHeader      SinkCategory = "http_header"     // HTTP response headers
	SnkTemplate    SinkCategory = "template_render" // Template rendering
	SnkDeserialize SinkCategory = "deserialize"     // Deserialization input
	SnkLog         SinkCategory = "log_output"      // Logging (log injection)
	SnkCrypto      SinkCategory = "crypto_input"    // Cryptographic operations
	SnkURLFetch    SinkCategory = "url_fetch"       // URL fetching (SSRF)
)

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
}

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
	Description   string         // Human description
	CWEID         string         // Associated CWE
	OWASPCategory string         // Associated OWASP category
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
	Name       string         // Variable name
	Line       int            // Line where it was last assigned
	Column     int            // Column
	Source     *SourceDef     // Origin source (nil = not tainted)
	SourceLine int            // Line where taint was introduced
	Sanitized  map[SinkCategory]bool // Which sink categories it's sanitized for
	Derived    bool           // True if taint was derived (e.g., x = tainted_var + "foo")
	Confidence float64        // 0.0 - 1.0, how sure we are this is tainted
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
	Source     SourceDef       // Where the untrusted data entered
	Sink       SinkDef         // Where the data was consumed dangerously
	SourceLine int             // Line of the source
	SinkLine   int             // Line of the sink
	Steps      []FlowStep      // Intermediate steps in the flow
	FilePath   string          // File being analyzed
	ScopeName  string          // Function/method scope
	Confidence float64         // Overall flow confidence
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

	return rules.Finding{
		RuleID:          "BATOU-TAINT-" + string(tf.Sink.Category),
		Severity:        tf.Sink.Severity,
		SeverityLabel:   tf.Sink.Severity.String(),
		Title:           title,
		Description:     desc,
		FilePath:        tf.FilePath,
		LineNumber:      tf.SinkLine,
		MatchedText:     matched,
		Suggestion:      suggestion,
		CWEID:           tf.Sink.CWEID,
		OWASPCategory:   tf.Sink.OWASPCategory,
		Confidence:      conf,
		ConfidenceScore: tf.Confidence,
		Tags:            []string{"taint-analysis", "dataflow", string(tf.Source.Category), string(tf.Sink.Category)},
	}
}

// Scope represents a code block (function, method, closure) being analyzed.
type Scope struct {
	Name      string      // Function/method name
	StartLine int         // First line of scope
	EndLine   int         // Last line of scope
	Params    []string    // Parameter names
	Body      string      // The source code within this scope
	Lines     []string    // Lines of the body
	Parent    *Scope      // Enclosing scope (nil for top-level)
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
