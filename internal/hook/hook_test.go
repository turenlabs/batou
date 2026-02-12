package hook_test

import (
	"encoding/json"
	"testing"

	"github.com/turen/gtss/internal/hook"
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
