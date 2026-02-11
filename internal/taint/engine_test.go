package taint_test

import (
	"strings"
	"testing"

	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"

	// Register all catalogs.
	_ "github.com/turen/gtss/internal/taint/languages"
)

// ---------------------------------------------------------------------------
// findSources / findSinks are unexported so we test them via Analyze.
// For unit-level source detection we use GetCatalog + Analyze on single-scope
// code snippets, verifying the flows or lack thereof.
// ---------------------------------------------------------------------------

func TestAnalyzeDetectsSources(t *testing.T) {
	tests := []struct {
		name    string
		lang    rules.Language
		code    string
		wantAny bool // expect at least one flow (source + sink present)
	}{
		{
			name: "Go FormValue source reaches sink",
			lang: rules.LangGo,
			code: `func handler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	rows, err := db.Query(username)
	_ = rows
	_ = err
}`,
			wantAny: true,
		},
		{
			name: "Go os.Getenv source reaches sink",
			lang: rules.LangGo,
			code: `func handler(w http.ResponseWriter, r *http.Request) {
	val := os.Getenv("SECRET")
	rows, err := db.Query(val)
	_ = rows
	_ = err
}`,
			wantAny: true,
		},
		{
			name: "JS req.body source reaches query sink",
			lang: rules.LangJavaScript,
			code: `function handler(req, res) {
	const data = req.body;
	db.query(data);
}`,
			wantAny: true,
		},
		{
			name:    "No source in plain Go code",
			lang:    rules.LangGo,
			code:    `func handler() { x := 42; _ = x }`,
			wantAny: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flows := taint.Analyze(tt.code, "test."+langExt(tt.lang), tt.lang)
			if tt.wantAny && len(flows) == 0 {
				t.Errorf("expected at least one taint flow, got none")
			}
			if !tt.wantAny && len(flows) > 0 {
				t.Errorf("expected no taint flows, got %d", len(flows))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Source-to-sink flow connectivity tests
// ---------------------------------------------------------------------------

func TestAnalyzeFlowConnectivity(t *testing.T) {
	tests := []struct {
		name        string
		lang        rules.Language
		code        string
		wantFlows   bool
		wantSinkCat taint.SinkCategory
	}{
		{
			name: "Go SQL injection via Sprintf",
			lang: rules.LangGo,
			code: `func handler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", username)
	rows, err := db.Query(query)
	_ = rows
	_ = err
}`,
			wantFlows:   true,
			wantSinkCat: taint.SnkSQLQuery,
		},
		{
			name: "Go command injection",
			lang: rules.LangGo,
			code: `func handler(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	cmd := exec.Command("ping", host)
	_ = cmd
}`,
			wantFlows:   true,
			wantSinkCat: taint.SnkCommand,
		},
		{
			name: "JS SQL injection via concatenation",
			lang: rules.LangJavaScript,
			code: `function search(req, res) {
	const term = req.query.q;
	const sql = "SELECT * FROM items WHERE name = '" + term + "'";
	db.query(sql);
}`,
			wantFlows:   true,
			wantSinkCat: taint.SnkSQLQuery,
		},
		{
			name: "Python SQL injection via f-string",
			lang: rules.LangPython,
			code: `def search(request):
    name = request.args.get("name")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
`,
			wantFlows:   true,
			wantSinkCat: taint.SnkSQLQuery,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flows := taint.Analyze(tt.code, "test."+langExt(tt.lang), tt.lang)
			if tt.wantFlows && len(flows) == 0 {
				t.Errorf("expected at least one taint flow, got none")
			}
			if tt.wantFlows && tt.wantSinkCat != "" {
				found := false
				for _, f := range flows {
					if f.Sink.Category == tt.wantSinkCat {
						found = true
						break
					}
				}
				if !found {
					cats := make([]string, len(flows))
					for i, f := range flows {
						cats[i] = string(f.Sink.Category)
					}
					t.Errorf("expected sink category %s, got %v", tt.wantSinkCat, cats)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Sanitizer breaks taint flow
// ---------------------------------------------------------------------------

func TestSanitizerBreaksFlow(t *testing.T) {
	code := `func handler(w http.ResponseWriter, r *http.Request) {
	userPath := r.FormValue("path")
	cleanPath := filepath.Base(userPath)
	f, err := os.Open(cleanPath)
	_ = f
	_ = err
}`
	flows := taint.Analyze(code, "test.go", rules.LangGo)

	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite && f.Source.Category == taint.SrcUserInput {
			t.Errorf("sanitizer should have broken taint flow, but found flow: %s -> %s",
				f.Source.MethodName, f.Sink.MethodName)
		}
	}
}

// ---------------------------------------------------------------------------
// Destructured variable extraction (JS { query } pattern)
// ---------------------------------------------------------------------------

func TestDestructuredVariableExtraction(t *testing.T) {
	// We verify destructured JS patterns by checking that taint flows are detected
	// when destructured variables reach sinks.
	tests := []struct {
		name string
		code string
	}{
		{
			name: "destructured query reaches eval",
			code: `function handler(req, res) {
	const { query } = req;
	eval(query);
}`,
		},
		{
			name: "destructured body reaches query",
			code: `function handler(req, res) {
	const { body } = req;
	db.query(body);
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flows := taint.Analyze(tt.code, "test.js", rules.LangJavaScript)
			if len(flows) == 0 {
				t.Error("expected taint flow from destructured variable to sink")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Multi-line sink argument handling
// ---------------------------------------------------------------------------

func TestMultiLineSinkArgs(t *testing.T) {
	// Multi-line calls should still be detected by the engine.
	code := `function handler(req, res) {
	const id = req.body.id;
	db.query(
		"SELECT * FROM users WHERE id = " + id
	);
}`
	flows := taint.Analyze(code, "test.js", rules.LangJavaScript)
	if len(flows) == 0 {
		t.Error("expected taint flow through multi-line sink call")
	}
}

// ---------------------------------------------------------------------------
// TaintFlow.ToFinding conversion
// ---------------------------------------------------------------------------

func TestTaintFlowToFinding(t *testing.T) {
	flow := taint.TaintFlow{
		Source: taint.SourceDef{
			Category:   taint.SrcUserInput,
			MethodName: "FormValue",
		},
		Sink: taint.SinkDef{
			Category:      taint.SnkSQLQuery,
			MethodName:    "Query",
			Severity:      rules.Critical,
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		SourceLine: 5,
		SinkLine:   10,
		FilePath:   "test.go",
		ScopeName:  "handler",
		Confidence: 0.9,
	}

	finding := flow.ToFinding()

	if finding.RuleID != "GTSS-TAINT-sql_query" {
		t.Errorf("expected RuleID 'GTSS-TAINT-sql_query', got %q", finding.RuleID)
	}
	if finding.Severity != rules.Critical {
		t.Errorf("expected Critical severity, got %s", finding.Severity)
	}
	if finding.CWEID != "CWE-89" {
		t.Errorf("expected CWE-89, got %q", finding.CWEID)
	}
	if !strings.Contains(finding.Title, "user_input") {
		t.Errorf("expected title to mention source category, got %q", finding.Title)
	}
	if !strings.Contains(finding.Title, "sql_query") {
		t.Errorf("expected title to mention sink category, got %q", finding.Title)
	}
	if finding.Confidence != "high" {
		t.Errorf("expected confidence 'high' for 0.9, got %q", finding.Confidence)
	}
	if len(finding.Tags) == 0 {
		t.Error("expected at least one tag")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func langExt(lang rules.Language) string {
	switch lang {
	case rules.LangGo:
		return "go"
	case rules.LangPython:
		return "py"
	case rules.LangJavaScript:
		return "js"
	case rules.LangTypeScript:
		return "ts"
	case rules.LangJava:
		return "java"
	case rules.LangC:
		return "c"
	case rules.LangCPP:
		return "cpp"
	case rules.LangPHP:
		return "php"
	case rules.LangRuby:
		return "rb"
	default:
		return "txt"
	}
}
