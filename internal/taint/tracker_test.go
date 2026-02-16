package taint_test

import (
	"testing"

	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"

	_ "github.com/turenlabs/batou/internal/taint/languages"
)

func TestTrackTaintBasicSourceToSink(t *testing.T) {
	// Variable becomes tainted when assigned from source, then reaches sink.
	code := `func handler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	rows, err := db.Query(username)
	_ = rows
	_ = err
}`
	flows := taint.Analyze(code, "test.go", rules.LangGo)
	if len(flows) == 0 {
		t.Error("expected at least one taint flow from source to sink")
	}
}

func TestTrackTaintPropagationChain(t *testing.T) {
	// Taint propagates through assignment chain: a -> b -> c -> sink.
	code := `func handler(w http.ResponseWriter, r *http.Request) {
	a := r.FormValue("input")
	b := a
	c := b
	d := "prefix" + c
	rows, err := db.Query(d)
	_ = rows
	_ = err
}`
	flows := taint.Analyze(code, "test.go", rules.LangGo)
	if len(flows) == 0 {
		t.Error("expected taint to propagate through assignment chain to sink")
	}

	// Verify the flow has intermediate steps.
	for _, flow := range flows {
		if flow.Sink.Category == taint.SnkSQLQuery {
			if len(flow.Steps) < 2 {
				t.Errorf("expected at least 2 steps in the flow chain, got %d", len(flow.Steps))
			}
			return
		}
	}
	t.Error("no SQL query sink flow found")
}

func TestTrackTaintSanitizerRemovesTaint(t *testing.T) {
	// strconv.Atoi sanitizes for SQL query sinks.
	code := `func handler(w http.ResponseWriter, r *http.Request) {
	idStr := r.FormValue("id")
	id := strconv.Atoi(idStr)
	rows, err := db.Query(id)
	_ = rows
	_ = err
}`
	flows := taint.Analyze(code, "test.go", rules.LangGo)

	for _, flow := range flows {
		if flow.Sink.Category == taint.SnkSQLQuery {
			for _, step := range flow.Steps {
				if step.VarName == "id" {
					t.Errorf("expected sanitizer to break taint flow for 'id', but flow still exists")
				}
			}
		}
	}
}

func TestTrackTaintUnknownFunctionPropagatesWithReducedConfidence(t *testing.T) {
	// Unknown function wrapping a tainted argument should propagate with 0.8x confidence.
	code := `func handler(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("data")
	processed := unknownFunction(input)
	rows, err := db.Query(processed)
	_ = rows
	_ = err
}`
	flows := taint.Analyze(code, "test.go", rules.LangGo)
	if len(flows) == 0 {
		t.Fatal("expected taint to propagate through unknown function")
	}

	for _, flow := range flows {
		if flow.Sink.Category == taint.SnkSQLQuery {
			if flow.Confidence > 0.85 {
				t.Errorf("expected reduced confidence through unknown function, got %.2f", flow.Confidence)
			}
			return
		}
	}
	t.Error("no SQL query flow found")
}

func TestTrackTaintNoFlowWithoutSink(t *testing.T) {
	// Source without sink should produce no flows.
	code := `func handler(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("data")
	_ = input
}`
	flows := taint.Analyze(code, "test.go", rules.LangGo)

	// Filter to flows that are actual source->sink (not log/other low-priority sinks).
	sqlFlows := 0
	cmdFlows := 0
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			sqlFlows++
		}
		if f.Sink.Category == taint.SnkCommand {
			cmdFlows++
		}
	}
	if sqlFlows > 0 {
		t.Errorf("expected no SQL flows without SQL sink, got %d", sqlFlows)
	}
	if cmdFlows > 0 {
		t.Errorf("expected no command flows without command sink, got %d", cmdFlows)
	}
}

func TestApplyPropagationRules(t *testing.T) {
	tests := []struct {
		name           string
		operation      string
		wantPropagates bool
		wantConfMin    float64
		wantConfMax    float64
	}{
		{
			name:           "string concat propagates",
			operation:      `"SELECT * FROM " + userInput`,
			wantPropagates: true,
			wantConfMin:    0.9,
			wantConfMax:    1.0,
		},
		{
			name:           "fmt.Sprintf propagates",
			operation:      `fmt.Sprintf("WHERE id = %s", input)`,
			wantPropagates: true,
			wantConfMin:    0.9,
			wantConfMax:    1.0,
		},
		{
			name:           "hash function does not propagate",
			operation:      `hashlib.sha256(data)`,
			wantPropagates: false,
			wantConfMin:    0.0,
			wantConfMax:    0.1,
		},
		{
			name:           "comparison does not propagate",
			operation:      `x == y`,
			wantPropagates: false,
			wantConfMin:    0.0,
			wantConfMax:    0.1,
		},
		{
			name:           "trim method propagates",
			operation:      `input.trim()`,
			wantPropagates: true,
			wantConfMin:    0.8,
			wantConfMax:    1.0,
		},
		{
			name:           "plain assignment propagates fully",
			operation:      `taintedVar`,
			wantPropagates: true,
			wantConfMin:    1.0,
			wantConfMax:    1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			propagates, confidence := taint.ApplyPropagation(tt.operation)
			if propagates != tt.wantPropagates {
				t.Errorf("ApplyPropagation(%q) propagates = %v, want %v", tt.operation, propagates, tt.wantPropagates)
			}
			if confidence < tt.wantConfMin || confidence > tt.wantConfMax {
				t.Errorf("ApplyPropagation(%q) confidence = %.2f, want [%.2f, %.2f]",
					tt.operation, confidence, tt.wantConfMin, tt.wantConfMax)
			}
		})
	}
}

func TestTaintVarIsTaintedFor(t *testing.T) {
	tests := []struct {
		name      string
		tv        taint.TaintVar
		cat       taint.SinkCategory
		wantTaint bool
	}{
		{
			name: "tainted and not sanitized",
			tv: taint.TaintVar{
				Source:    &taint.SourceDef{Category: taint.SrcUserInput},
				Sanitized: map[taint.SinkCategory]bool{},
			},
			cat:       taint.SnkSQLQuery,
			wantTaint: true,
		},
		{
			name: "tainted but sanitized for this category",
			tv: taint.TaintVar{
				Source:    &taint.SourceDef{Category: taint.SrcUserInput},
				Sanitized: map[taint.SinkCategory]bool{taint.SnkSQLQuery: true},
			},
			cat:       taint.SnkSQLQuery,
			wantTaint: false,
		},
		{
			name: "tainted and sanitized for different category",
			tv: taint.TaintVar{
				Source:    &taint.SourceDef{Category: taint.SrcUserInput},
				Sanitized: map[taint.SinkCategory]bool{taint.SnkHTMLOutput: true},
			},
			cat:       taint.SnkSQLQuery,
			wantTaint: true,
		},
		{
			name: "not tainted (no source)",
			tv: taint.TaintVar{
				Source:    nil,
				Sanitized: map[taint.SinkCategory]bool{},
			},
			cat:       taint.SnkSQLQuery,
			wantTaint: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tv.IsTaintedFor(tt.cat)
			if got != tt.wantTaint {
				t.Errorf("IsTaintedFor(%s) = %v, want %v", tt.cat, got, tt.wantTaint)
			}
		})
	}
}
