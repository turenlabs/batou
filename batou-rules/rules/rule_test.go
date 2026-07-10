package rules

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFinding_TaintPathJSONRoundTrip(t *testing.T) {
	f := Finding{
		RuleID:     "BATOU-TAINT-sql_query",
		Severity:   Critical,
		Title:      "Tainted data flows to SQL query",
		FilePath:   "/app/handler.go",
		LineNumber: 120,
		CWEID:      "CWE-89",
		TaintPath: []TaintStep{
			{File: "/app/handler.go", Line: 42, Kind: TaintStepSource, Label: "request.args.get('id')"},
			{File: "/app/service.go", Line: 88, Kind: TaintStepPropagation, Label: "passed to buildQuery(id)"},
			{File: "/app/repo.go", Line: 120, Column: 5, Kind: TaintStepSink, Label: "cursor.execute(query)", Snippet: "cursor.execute(query)"},
		},
	}

	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"taint_path"`) {
		t.Fatalf("expected taint_path key in JSON, got: %s", b)
	}

	var got Finding
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.TaintPath) != 3 {
		t.Fatalf("expected 3 path steps after round-trip, got %d", len(got.TaintPath))
	}
	if got.TaintPath[0].Kind != TaintStepSource || got.TaintPath[0].Line != 42 || got.TaintPath[0].File != "/app/handler.go" {
		t.Errorf("source step round-tripped wrong: %+v", got.TaintPath[0])
	}
	if got.TaintPath[2].Kind != TaintStepSink || got.TaintPath[2].Column != 5 || got.TaintPath[2].Snippet != "cursor.execute(query)" {
		t.Errorf("sink step round-tripped wrong: %+v", got.TaintPath[2])
	}
}

func TestFinding_TaintPathOmittedWhenEmpty(t *testing.T) {
	f := Finding{RuleID: "BATOU-INJ-001", Severity: High, FilePath: "/app/x.go", LineNumber: 1}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "taint_path") {
		t.Errorf("expected taint_path to be omitted when empty, got: %s", b)
	}
}

func TestFinding_FormatTaintPath(t *testing.T) {
	f := Finding{
		CWEID: "CWE-89",
		TaintPath: []TaintStep{
			{File: "h.go", Line: 1, Kind: TaintStepSource, Label: "req.args"},
			{File: "s.go", Line: 2, Kind: TaintStepPropagation, Label: "to q()"},
			{File: "r.go", Line: 3, Kind: TaintStepSink, Label: "execute(q)"},
		},
	}
	out := f.FormatTaintPath()
	for _, want := range []string{"Data-flow path:", "h.go:1", "s.go:2", "r.go:3", "source:", "sink:", "CWE-89"} {
		if !strings.Contains(out, want) {
			t.Errorf("FormatTaintPath() missing %q in:\n%s", want, out)
		}
	}

	empty := Finding{}
	if empty.FormatTaintPath() != "" {
		t.Errorf("expected empty string for finding with no TaintPath, got %q", empty.FormatTaintPath())
	}
}
