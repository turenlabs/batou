package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Input represents the JSON received from Claude Code hooks via stdin.
type Input struct {
	SessionID      string         `json:"session_id"`
	TranscriptPath string         `json:"transcript_path"`
	Cwd            string         `json:"cwd"`
	PermissionMode string         `json:"permission_mode"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      ToolInput      `json:"tool_input"`
	ToolResponse   ToolResponse   `json:"tool_response"`
	ToolUseID      string         `json:"tool_use_id"`
}

// ToolInput holds the input parameters of the tool being hooked.
type ToolInput struct {
	// Write tool fields
	FilePath string `json:"file_path"`
	Content  string `json:"content"`

	// Edit tool fields
	OldString  string `json:"old_string"`
	NewString  string `json:"new_string"`
	ReplaceAll bool   `json:"replace_all"`

	// NotebookEdit fields
	NotebookPath string `json:"notebook_path"`
	NewSource    string `json:"new_source"`
}

// ToolResponse holds the response from the tool after execution.
type ToolResponse struct {
	FilePath string `json:"filePath"`
	Success  bool   `json:"success"`
}

// OutputDecision represents a hook's decision for PreToolUse events.
type PreToolOutput struct {
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

type HookSpecificOutput struct {
	HookEventName          string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string `json:"additionalContext,omitempty"`
}

// PostToolOutput represents a hook's output for PostToolUse events.
type PostToolOutput struct {
	AdditionalContext string `json:"additionalContext,omitempty"`
}

// maxInputSize is the maximum bytes we'll read from stdin (50 MB).
// Prevents OOM on very large file writes (e.g., minified JS bundles).
const maxInputSize = 50 * 1024 * 1024

// ReadInput reads and parses the hook input from stdin.
func ReadInput() (*Input, error) {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxInputSize))
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}

	var input Input
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("parsing hook input: %w", err)
	}

	return &input, nil
}

// ResolvePath returns the file path from the hook input, handling
// different tool types (Write, Edit, NotebookEdit).
func (i *Input) ResolvePath() string {
	if i.ToolInput.FilePath != "" {
		return i.ToolInput.FilePath
	}
	if i.ToolInput.NotebookPath != "" {
		return i.ToolInput.NotebookPath
	}
	if i.ToolResponse.FilePath != "" {
		return i.ToolResponse.FilePath
	}
	return ""
}

// ResolveContent returns the content being written/edited.
// For Write: returns the full content.
// For Edit: returns the new_string (replacement text).
// For NotebookEdit: returns the new_source.
func (i *Input) ResolveContent() string {
	if i.ToolInput.Content != "" {
		return i.ToolInput.Content
	}
	if i.ToolInput.NewString != "" {
		return i.ToolInput.NewString
	}
	if i.ToolInput.NewSource != "" {
		return i.ToolInput.NewSource
	}
	return ""
}

// IsPreToolUse returns true if this is a pre-execution hook.
func (i *Input) IsPreToolUse() bool {
	return i.HookEventName == "PreToolUse"
}

// IsPostToolUse returns true if this is a post-execution hook.
func (i *Input) IsPostToolUse() bool {
	return i.HookEventName == "PostToolUse"
}

// IsWriteOperation returns true if the tool is writing a new file.
func (i *Input) IsWriteOperation() bool {
	return i.ToolName == "Write"
}

// IsEditOperation returns true if the tool is editing an existing file.
func (i *Input) IsEditOperation() bool {
	return i.ToolName == "Edit"
}

// BlockWrite outputs to stderr and exits with code 2 to block a write.
func BlockWrite(message string) {
	fmt.Fprint(os.Stderr, message)
	os.Exit(2)
}

// OutputPreTool writes a PreToolUse JSON response to stdout.
func OutputPreTool(decision, reason, context string) error {
	out := PreToolOutput{
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName:           "PreToolUse",
			PermissionDecision:       decision,
			PermissionDecisionReason: reason,
			AdditionalContext:        context,
		},
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

// OutputPostTool writes a PostToolUse JSON response to stdout.
func OutputPostTool(context string) error {
	out := PostToolOutput{
		AdditionalContext: context,
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}
