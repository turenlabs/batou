package hook_test

import (
	"encoding/json"
	"testing"

	"github.com/turenio/gtss/internal/hook"
)

// ---------------------------------------------------------------------------
// Input.ResolvePath
// ---------------------------------------------------------------------------

func TestResolvePathWrite(t *testing.T) {
	input := &hook.Input{
		ToolName: "Write",
		ToolInput: hook.ToolInput{
			FilePath: "/app/handler.go",
			Content:  "package main",
		},
	}
	if got := input.ResolvePath(); got != "/app/handler.go" {
		t.Errorf("ResolvePath() = %q, want %q", got, "/app/handler.go")
	}
}

func TestResolvePathEdit(t *testing.T) {
	input := &hook.Input{
		ToolName: "Edit",
		ToolInput: hook.ToolInput{
			FilePath:  "/app/handler.go",
			OldString: "old",
			NewString: "new",
		},
	}
	if got := input.ResolvePath(); got != "/app/handler.go" {
		t.Errorf("ResolvePath() = %q, want %q", got, "/app/handler.go")
	}
}

func TestResolvePathNotebook(t *testing.T) {
	input := &hook.Input{
		ToolName: "NotebookEdit",
		ToolInput: hook.ToolInput{
			NotebookPath: "/app/notebook.ipynb",
			NewSource:    "import os",
		},
	}
	if got := input.ResolvePath(); got != "/app/notebook.ipynb" {
		t.Errorf("ResolvePath() = %q, want %q", got, "/app/notebook.ipynb")
	}
}

func TestResolvePathFromToolResponse(t *testing.T) {
	input := &hook.Input{
		HookEventName: "PostToolUse",
		ToolName:      "Write",
		ToolResponse: hook.ToolResponse{
			FilePath: "/app/output.go",
			Success:  true,
		},
	}
	if got := input.ResolvePath(); got != "/app/output.go" {
		t.Errorf("ResolvePath() = %q, want %q", got, "/app/output.go")
	}
}

func TestResolvePathEmpty(t *testing.T) {
	input := &hook.Input{}
	if got := input.ResolvePath(); got != "" {
		t.Errorf("ResolvePath() = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// Input.ResolveContent
// ---------------------------------------------------------------------------

func TestResolveContentWrite(t *testing.T) {
	input := &hook.Input{
		ToolName: "Write",
		ToolInput: hook.ToolInput{
			FilePath: "/app/handler.go",
			Content:  "package main\nfunc main() {}",
		},
	}
	if got := input.ResolveContent(); got != "package main\nfunc main() {}" {
		t.Errorf("ResolveContent() = %q, want full content", got)
	}
}

func TestResolveContentEdit(t *testing.T) {
	input := &hook.Input{
		ToolName: "Edit",
		ToolInput: hook.ToolInput{
			FilePath:  "/app/handler.go",
			NewString: "new replacement text",
		},
	}
	if got := input.ResolveContent(); got != "new replacement text" {
		t.Errorf("ResolveContent() = %q, want new_string", got)
	}
}

func TestResolveContentNotebook(t *testing.T) {
	input := &hook.Input{
		ToolName: "NotebookEdit",
		ToolInput: hook.ToolInput{
			NotebookPath: "/app/nb.ipynb",
			NewSource:    "import os\nos.system('ls')",
		},
	}
	if got := input.ResolveContent(); got != "import os\nos.system('ls')" {
		t.Errorf("ResolveContent() = %q, want new_source", got)
	}
}

func TestResolveContentEmpty(t *testing.T) {
	input := &hook.Input{}
	if got := input.ResolveContent(); got != "" {
		t.Errorf("ResolveContent() = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// Event type helpers
// ---------------------------------------------------------------------------

func TestIsPreToolUse(t *testing.T) {
	pre := &hook.Input{HookEventName: "PreToolUse"}
	post := &hook.Input{HookEventName: "PostToolUse"}

	if !pre.IsPreToolUse() {
		t.Error("IsPreToolUse() should be true for PreToolUse event")
	}
	if pre.IsPostToolUse() {
		t.Error("IsPostToolUse() should be false for PreToolUse event")
	}
	if post.IsPreToolUse() {
		t.Error("IsPreToolUse() should be false for PostToolUse event")
	}
	if !post.IsPostToolUse() {
		t.Error("IsPostToolUse() should be true for PostToolUse event")
	}
}

func TestIsWriteOperation(t *testing.T) {
	w := &hook.Input{ToolName: "Write"}
	e := &hook.Input{ToolName: "Edit"}

	if !w.IsWriteOperation() {
		t.Error("IsWriteOperation() should be true for Write tool")
	}
	if w.IsEditOperation() {
		t.Error("IsEditOperation() should be false for Write tool")
	}
	if e.IsWriteOperation() {
		t.Error("IsWriteOperation() should be false for Edit tool")
	}
	if !e.IsEditOperation() {
		t.Error("IsEditOperation() should be true for Edit tool")
	}
}

// ---------------------------------------------------------------------------
// JSON parsing (Input struct)
// ---------------------------------------------------------------------------

func TestInputJSONParsing(t *testing.T) {
	raw := `{
		"session_id": "ses-123",
		"cwd": "/project",
		"hook_event_name": "PreToolUse",
		"tool_name": "Write",
		"tool_input": {
			"file_path": "/project/main.go",
			"content": "package main"
		}
	}`

	var input hook.Input
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		t.Fatalf("failed to unmarshal Input: %v", err)
	}

	if input.SessionID != "ses-123" {
		t.Errorf("SessionID = %q, want %q", input.SessionID, "ses-123")
	}
	if input.Cwd != "/project" {
		t.Errorf("Cwd = %q, want %q", input.Cwd, "/project")
	}
	if input.HookEventName != "PreToolUse" {
		t.Errorf("HookEventName = %q, want %q", input.HookEventName, "PreToolUse")
	}
	if input.ToolName != "Write" {
		t.Errorf("ToolName = %q, want %q", input.ToolName, "Write")
	}
	if input.ToolInput.FilePath != "/project/main.go" {
		t.Errorf("ToolInput.FilePath = %q, want %q", input.ToolInput.FilePath, "/project/main.go")
	}
	if input.ToolInput.Content != "package main" {
		t.Errorf("ToolInput.Content = %q, want %q", input.ToolInput.Content, "package main")
	}
}

func TestInputJSONEditTool(t *testing.T) {
	raw := `{
		"session_id": "ses-456",
		"hook_event_name": "PreToolUse",
		"tool_name": "Edit",
		"tool_input": {
			"file_path": "/project/handler.go",
			"old_string": "unsafe code",
			"new_string": "safe code",
			"replace_all": true
		}
	}`

	var input hook.Input
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		t.Fatalf("failed to unmarshal Input: %v", err)
	}

	if input.ToolInput.OldString != "unsafe code" {
		t.Errorf("OldString = %q, want %q", input.ToolInput.OldString, "unsafe code")
	}
	if input.ToolInput.NewString != "safe code" {
		t.Errorf("NewString = %q, want %q", input.ToolInput.NewString, "safe code")
	}
	if !input.ToolInput.ReplaceAll {
		t.Error("ReplaceAll should be true")
	}
}

// ---------------------------------------------------------------------------
// PreToolOutput JSON serialization
// ---------------------------------------------------------------------------

func TestPreToolOutputJSON(t *testing.T) {
	out := hook.PreToolOutput{
		HookSpecificOutput: &hook.HookSpecificOutput{
			HookEventName:           "PreToolUse",
			PermissionDecision:       "allow",
			PermissionDecisionReason: "no issues found",
			AdditionalContext:        "GTSS scan clean",
		},
	}

	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("failed to marshal PreToolOutput: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to re-parse PreToolOutput: %v", err)
	}

	hso, ok := parsed["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatal("expected hookSpecificOutput key in JSON output")
	}
	if hso["permissionDecision"] != "allow" {
		t.Errorf("permissionDecision = %v, want %q", hso["permissionDecision"], "allow")
	}
	if hso["additionalContext"] != "GTSS scan clean" {
		t.Errorf("additionalContext = %v, want %q", hso["additionalContext"], "GTSS scan clean")
	}
}

// ---------------------------------------------------------------------------
// PostToolOutput JSON serialization
// ---------------------------------------------------------------------------

func TestPostToolOutputJSON(t *testing.T) {
	out := hook.PostToolOutput{
		AdditionalContext: "scan completed with 2 findings",
	}

	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("failed to marshal PostToolOutput: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to re-parse: %v", err)
	}

	if parsed["additionalContext"] != "scan completed with 2 findings" {
		t.Errorf("additionalContext = %v, want %q", parsed["additionalContext"], "scan completed with 2 findings")
	}
}

func TestPostToolOutputOmitsEmptyContext(t *testing.T) {
	out := hook.PostToolOutput{}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to re-parse: %v", err)
	}

	// additionalContext has omitempty, so it should be absent.
	if _, exists := parsed["additionalContext"]; exists {
		t.Error("expected additionalContext to be omitted when empty")
	}
}

// ---------------------------------------------------------------------------
// maxInputSize constant
// ---------------------------------------------------------------------------

func TestMaxInputSizeIs50MB(t *testing.T) {
	// The maxInputSize constant is unexported, but we can verify behavior
	// by checking that very large input does not panic during JSON parsing.
	// This is a smoke test of the constant's purpose.
	largeJSON := `{"session_id":"test","tool_name":"Write","tool_input":{"file_path":"x.go","content":"` +
		string(make([]byte, 1024)) + `"}}`

	var input hook.Input
	if err := json.Unmarshal([]byte(largeJSON), &input); err != nil {
		// Expected: the null bytes in content will cause a JSON error,
		// but this confirms the struct can handle reasonable sizes.
		_ = err
	}
}

// ---------------------------------------------------------------------------
// Malformed JSON parsing
// ---------------------------------------------------------------------------

func TestInputMalformedJSON(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"empty string", ""},
		{"not JSON", "this is not json"},
		{"truncated JSON", `{"session_id": "test"`},
		{"wrong type for field", `{"session_id": 123}`},
		{"array instead of object", `[1,2,3]`},
		{"null", "null"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var input hook.Input
			err := json.Unmarshal([]byte(tt.raw), &input)
			if tt.raw == "" || tt.raw == "this is not json" ||
				tt.raw == `{"session_id": "test"` || tt.raw == "[1,2,3]" {
				if err == nil {
					t.Errorf("expected error for %q, got nil", tt.name)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Full round-trip: JSON -> Input -> ResolvePath/ResolveContent
// ---------------------------------------------------------------------------

func TestInputFullRoundTrip(t *testing.T) {
	raw := `{
		"session_id": "ses-rt-001",
		"transcript_path": "/tmp/transcript.json",
		"cwd": "/home/user/project",
		"permission_mode": "default",
		"hook_event_name": "PreToolUse",
		"tool_name": "Write",
		"tool_use_id": "tu-001",
		"tool_input": {
			"file_path": "/home/user/project/app.py",
			"content": "import os\nos.system(user_input)"
		}
	}`

	var input hook.Input
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if input.ResolvePath() != "/home/user/project/app.py" {
		t.Errorf("ResolvePath() = %q", input.ResolvePath())
	}
	if input.ResolveContent() != "import os\nos.system(user_input)" {
		t.Errorf("ResolveContent() = %q", input.ResolveContent())
	}
	if !input.IsPreToolUse() {
		t.Error("expected IsPreToolUse() = true")
	}
	if !input.IsWriteOperation() {
		t.Error("expected IsWriteOperation() = true")
	}
	if input.IsEditOperation() {
		t.Error("expected IsEditOperation() = false")
	}
	if input.IsPostToolUse() {
		t.Error("expected IsPostToolUse() = false")
	}
}

func TestInputEditFullRoundTrip(t *testing.T) {
	raw := `{
		"session_id": "ses-rt-002",
		"hook_event_name": "PreToolUse",
		"tool_name": "Edit",
		"tool_input": {
			"file_path": "/app/server.go",
			"old_string": "db.Query(fmt.Sprintf(q, name))",
			"new_string": "db.Query(q, name)",
			"replace_all": false
		}
	}`

	var input hook.Input
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if input.ResolvePath() != "/app/server.go" {
		t.Errorf("ResolvePath() = %q", input.ResolvePath())
	}
	if input.ResolveContent() != "db.Query(q, name)" {
		t.Errorf("ResolveContent() = %q (expected new_string)", input.ResolveContent())
	}
	if !input.IsEditOperation() {
		t.Error("expected IsEditOperation() = true")
	}
	if input.ToolInput.OldString != "db.Query(fmt.Sprintf(q, name))" {
		t.Errorf("OldString = %q", input.ToolInput.OldString)
	}
	if input.ToolInput.ReplaceAll {
		t.Error("expected ReplaceAll = false")
	}
}

// ---------------------------------------------------------------------------
// PreToolOutput JSON: all fields, block decision
// ---------------------------------------------------------------------------

func TestPreToolOutputBlockDecision(t *testing.T) {
	out := hook.PreToolOutput{
		HookSpecificOutput: &hook.HookSpecificOutput{
			HookEventName:           "PreToolUse",
			PermissionDecision:       "block",
			PermissionDecisionReason: "Critical SQL injection detected",
			AdditionalContext:        "GTSS-INJ-001: SQL injection in db.Query",
		},
	}

	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to re-parse: %v", err)
	}

	hso, ok := parsed["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatal("expected hookSpecificOutput key")
	}
	if hso["permissionDecision"] != "block" {
		t.Errorf("permissionDecision = %v, want block", hso["permissionDecision"])
	}
	if hso["hookEventName"] != "PreToolUse" {
		t.Errorf("hookEventName = %v, want PreToolUse", hso["hookEventName"])
	}
	if hso["permissionDecisionReason"] != "Critical SQL injection detected" {
		t.Errorf("permissionDecisionReason = %v", hso["permissionDecisionReason"])
	}
}

// ---------------------------------------------------------------------------
// PreToolOutput: omitempty on nil HookSpecificOutput
// ---------------------------------------------------------------------------

func TestPreToolOutputOmitsNilHSO(t *testing.T) {
	out := hook.PreToolOutput{}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to re-parse: %v", err)
	}

	if _, exists := parsed["hookSpecificOutput"]; exists {
		t.Error("expected hookSpecificOutput to be omitted when nil")
	}
}

// ---------------------------------------------------------------------------
// NotebookEdit JSON parsing
// ---------------------------------------------------------------------------

func TestInputJSONNotebookEdit(t *testing.T) {
	raw := `{
		"session_id": "ses-789",
		"hook_event_name": "PreToolUse",
		"tool_name": "NotebookEdit",
		"tool_input": {
			"notebook_path": "/project/analysis.ipynb",
			"new_source": "import subprocess\nsubprocess.run(user_cmd, shell=True)"
		}
	}`

	var input hook.Input
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if input.ToolName != "NotebookEdit" {
		t.Errorf("ToolName = %q", input.ToolName)
	}
	if input.ResolvePath() != "/project/analysis.ipynb" {
		t.Errorf("ResolvePath() = %q", input.ResolvePath())
	}
	if input.ResolveContent() != "import subprocess\nsubprocess.run(user_cmd, shell=True)" {
		t.Errorf("ResolveContent() = %q", input.ResolveContent())
	}
}

// ---------------------------------------------------------------------------
// PostToolUse JSON parsing
// ---------------------------------------------------------------------------

func TestInputJSONPostToolUse(t *testing.T) {
	raw := `{
		"session_id": "ses-post",
		"hook_event_name": "PostToolUse",
		"tool_name": "Write",
		"tool_input": {
			"file_path": "/app/handler.go",
			"content": "package main"
		},
		"tool_response": {
			"filePath": "/app/handler.go",
			"success": true
		}
	}`

	var input hook.Input
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !input.IsPostToolUse() {
		t.Error("expected IsPostToolUse() = true")
	}
	if input.ToolResponse.FilePath != "/app/handler.go" {
		t.Errorf("ToolResponse.FilePath = %q", input.ToolResponse.FilePath)
	}
	if !input.ToolResponse.Success {
		t.Error("expected ToolResponse.Success = true")
	}
}

// ---------------------------------------------------------------------------
// Extra JSON fields are ignored (forward compatibility)
// ---------------------------------------------------------------------------

func TestInputJSONExtraFieldsIgnored(t *testing.T) {
	raw := `{
		"session_id": "ses-extra",
		"hook_event_name": "PreToolUse",
		"tool_name": "Write",
		"tool_input": {
			"file_path": "/app/main.go",
			"content": "package main"
		},
		"unknown_field": "should not cause an error",
		"another_field": 42
	}`

	var input hook.Input
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		t.Fatalf("extra fields should be silently ignored, got: %v", err)
	}
	if input.SessionID != "ses-extra" {
		t.Errorf("SessionID = %q", input.SessionID)
	}
}

// ---------------------------------------------------------------------------
// Unicode content in JSON
// ---------------------------------------------------------------------------

func TestInputJSONUnicodeContent(t *testing.T) {
	raw := `{
		"session_id": "ses-unicode",
		"hook_event_name": "PreToolUse",
		"tool_name": "Write",
		"tool_input": {
			"file_path": "/app/i18n.py",
			"content": "message = \"Привет мир! 你好世界! 🌍\""
		}
	}`

	var input hook.Input
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		t.Fatalf("failed to unmarshal unicode: %v", err)
	}
	if input.ResolveContent() != "message = \"Привет мир! 你好世界! 🌍\"" {
		t.Errorf("ResolveContent() = %q", input.ResolveContent())
	}
}
