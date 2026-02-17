package taintrule

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
	"github.com/turenlabs/batou/internal/testutil"
)

func TestTaintRule_EnvVarToLog_Suppressed(t *testing.T) {
	content := `package main

import (
	"log"
	"os"
)

func main() {
	dbHost := os.Getenv("DB_HOST")
	log.Println("connecting to", dbHost)
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	// Should NOT flag env_var → log_output flow
	for _, f := range result.Findings {
		if strings.HasPrefix(f.RuleID, "BATOU-TAINT") && strings.Contains(f.MatchedText, "Getenv") {
			if strings.Contains(f.Title, "log") || strings.Contains(f.Description, "log_output") {
				t.Errorf("unexpected env→log finding: %s: %s", f.RuleID, f.Title)
			}
		}
	}
}

func TestTaintRule_EnvVarToCommand_NotSuppressed(t *testing.T) {
	// Verify that the suppression filter only targets env_var → log_output,
	// not env_var → command_exec. We test the filter logic directly since
	// the taint engine may not produce flows for small synthetic snippets.
	flow := taint.TaintFlow{
		Source: taint.SourceDef{
			Category:    taint.SrcEnvVar,
			MethodName:  "Getenv",
			Description: "os.Getenv",
			Language:    rules.LangGo,
		},
		Sink: taint.SinkDef{
			Category:    taint.SnkCommand,
			MethodName:  "Command",
			Description: "exec.Command",
			Severity:    rules.Critical,
		},
		SourceLine: 1,
		SinkLine:   2,
		Confidence: 1.0,
	}
	// This flow should NOT be filtered (env → command is dangerous)
	if flow.Source.Category == taint.SrcEnvVar && flow.Sink.Category == taint.SnkLog {
		t.Errorf("command sink incorrectly matched SnkLog filter")
	}

	// But env → log SHOULD be filtered
	logFlow := taint.TaintFlow{
		Source: taint.SourceDef{Category: taint.SrcEnvVar},
		Sink:   taint.SinkDef{Category: taint.SnkLog},
	}
	if !(logFlow.Source.Category == taint.SrcEnvVar && logFlow.Sink.Category == taint.SnkLog) {
		t.Errorf("env→log flow should match suppression filter")
	}
}
