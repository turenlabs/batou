// Package graph implements a persistent, session-aware call graph that tracks
// function relationships across the entire project. As Claude writes and edits
// code, the graph is incrementally updated so that Batou can perform interprocedural
// taint analysis — tracing data flow across function call boundaries.
//
// The graph persists to .batou/callgraph.json in the project root so it survives
// across individual hook invocations within a session.
//
// When function B is modified:
//  1. Re-parse B, update its node in the graph
//  2. Diff B's taint signature (which params are sources, which returns carry taint)
//  3. If the signature changed, walk all callers of B and re-analyze them
//  4. Propagate transitively until no more changes
package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// CallGraph is the project-wide function relationship graph.
type CallGraph struct {
	// Nodes maps function IDs to their metadata.
	Nodes map[string]*FuncNode `json:"nodes"`

	// ProjectRoot is the project directory this graph belongs to.
	ProjectRoot string `json:"project_root"`

	// SessionID tracks which Claude session built this graph.
	SessionID string `json:"session_id"`

	// LastUpdated is when the graph was last modified.
	LastUpdated time.Time `json:"last_updated"`

	// Version for format compatibility.
	Version int `json:"version"`
}

// FuncNode represents a single function/method in the call graph.
type FuncNode struct {
	// Identity
	ID       string `json:"id"`        // Unique: "filepath:FuncName" or "filepath:Receiver.Method"
	FilePath string `json:"file_path"` // Absolute path to the source file
	Name     string `json:"name"`      // Function/method name
	Package  string `json:"package"`   // Package name (Go) or module (Python/JS)

	// Location
	StartLine int `json:"start_line"`
	EndLine   int `json:"end_line"`

	// Call relationships
	Calls    []string `json:"calls"`     // IDs of functions this node calls
	CalledBy []string `json:"called_by"` // IDs of functions that call this node

	// Taint signature — the security-relevant interface of this function.
	// This is what changes when we need to re-analyze callers.
	TaintSig TaintSignature `json:"taint_sig"`

	// Change tracking
	ContentHash string    `json:"content_hash"` // SHA-256 of the function body
	LastScanAt  time.Time `json:"last_scan_at"` // When this node was last analyzed
	Language    rules.Language `json:"language"`

	// Findings from intraprocedural analysis of this function
	FindingCount int `json:"finding_count"`
}

// TaintSignature describes how taint flows through a function's interface.
// When this changes, all callers need re-analysis.
type TaintSignature struct {
	// TaintedParams lists which parameters carry taint from callers.
	// Key: param index, Value: what categories of taint
	TaintedParams map[int][]taint.SourceCategory `json:"tainted_params,omitempty"`

	// TaintedReturns lists which return values carry taint.
	// Key: return index, Value: what categories of taint
	TaintedReturns map[int][]taint.SourceCategory `json:"tainted_returns,omitempty"`

	// SourceParams lists parameters that are direct taint sources
	// (e.g., *http.Request parameters in HTTP handlers).
	SourceParams map[int]taint.SourceCategory `json:"source_params,omitempty"`

	// SinkCalls lists dangerous sink calls inside this function
	// that consume tainted data from parameters.
	SinkCalls []SinkRef `json:"sink_calls,omitempty"`

	// SuppressedSinks lists sink calls that were suppressed by
	// batou:ignore directives. Callers skip these sinks during
	// interprocedural analysis.
	SuppressedSinks []SinkRef `json:"suppressed_sinks,omitempty"`

	// SanitizedPaths notes which param→sink paths pass through sanitizers.
	SanitizedPaths []SanitizedPath `json:"sanitized_paths,omitempty"`

	// IsPure is true if this function has no security-relevant side effects
	// and doesn't propagate taint (e.g., pure math, string formatting).
	IsPure bool `json:"is_pure,omitempty"`
}

// SinkRef records a sink call inside a function.
type SinkRef struct {
	SinkCategory taint.SinkCategory `json:"category"`
	MethodName   string             `json:"method"`
	Line         int                `json:"line"`
	ArgFromParam int                `json:"arg_from_param"` // Which param flows to this sink (-1 if none)
}

// SanitizedPath records that taint from a param is sanitized before reaching a sink.
type SanitizedPath struct {
	ParamIndex    int                `json:"param_index"`
	SinkCategory  taint.SinkCategory `json:"sink_category"`
	SanitizerName string             `json:"sanitizer_name"`
	SanitizerLine int                `json:"sanitizer_line"`
}

// ImpactedCaller describes a caller that may be affected by a function change.
type ImpactedCaller struct {
	CallerID   string         // ID of the caller function
	CallerNode *FuncNode      // The caller's node
	CallLine   int            // Line where the call happens
	Reason     string         // Why this caller is impacted
	Severity   rules.Severity // How serious the impact is
}

// NewCallGraph creates an empty call graph.
func NewCallGraph(projectRoot, sessionID string) *CallGraph {
	return &CallGraph{
		Nodes:       make(map[string]*FuncNode),
		ProjectRoot: projectRoot,
		SessionID:   sessionID,
		LastUpdated: time.Now(),
		Version:     1,
	}
}

// FuncID generates a unique ID for a function.
func FuncID(filePath, funcName string) string {
	return filePath + ":" + funcName
}

// ContentHash computes a SHA-256 hash of function body content.
func ContentHash(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:8]) // First 8 bytes = 16 hex chars
}

// AddNode adds or updates a function node in the graph.
func (cg *CallGraph) AddNode(node *FuncNode) {
	cg.Nodes[node.ID] = node
	cg.LastUpdated = time.Now()
}

// GetNode returns a node by ID, or nil if not found.
func (cg *CallGraph) GetNode(id string) *FuncNode {
	return cg.Nodes[id]
}

// AddEdge records that caller calls callee.
func (cg *CallGraph) AddEdge(callerID, calleeID string) {
	caller := cg.Nodes[callerID]
	callee := cg.Nodes[calleeID]
	if caller == nil || callee == nil {
		return
	}

	// Add to caller's Calls if not already present
	if !containsStr(caller.Calls, calleeID) {
		caller.Calls = append(caller.Calls, calleeID)
	}
	// Add to callee's CalledBy if not already present
	if !containsStr(callee.CalledBy, callerID) {
		callee.CalledBy = append(callee.CalledBy, callerID)
	}
}

// RemoveEdge removes a call relationship.
func (cg *CallGraph) RemoveEdge(callerID, calleeID string) {
	caller := cg.Nodes[callerID]
	callee := cg.Nodes[calleeID]
	if caller != nil {
		caller.Calls = removeStr(caller.Calls, calleeID)
	}
	if callee != nil {
		callee.CalledBy = removeStr(callee.CalledBy, callerID)
	}
}

// GetCallers returns all nodes that call the given function.
func (cg *CallGraph) GetCallers(funcID string) []*FuncNode {
	node := cg.Nodes[funcID]
	if node == nil {
		return nil
	}
	callers := make([]*FuncNode, 0, len(node.CalledBy))
	for _, callerID := range node.CalledBy {
		if caller := cg.Nodes[callerID]; caller != nil {
			callers = append(callers, caller)
		}
	}
	return callers
}

// GetCallees returns all nodes that the given function calls.
func (cg *CallGraph) GetCallees(funcID string) []*FuncNode {
	node := cg.Nodes[funcID]
	if node == nil {
		return nil
	}
	callees := make([]*FuncNode, 0, len(node.Calls))
	for _, calleeID := range node.Calls {
		if callee := cg.Nodes[calleeID]; callee != nil {
			callees = append(callees, callee)
		}
	}
	return callees
}

// GetTransitiveCallers walks the graph upward and returns all functions
// that transitively depend on the given function (breadth-first).
func (cg *CallGraph) GetTransitiveCallers(funcID string, maxDepth int) []*FuncNode {
	visited := make(map[string]bool)
	visited[funcID] = true
	var result []*FuncNode

	queue := []string{funcID}
	depth := 0

	for len(queue) > 0 && depth < maxDepth {
		nextQueue := []string{}
		for _, id := range queue {
			node := cg.Nodes[id]
			if node == nil {
				continue
			}
			for _, callerID := range node.CalledBy {
				if !visited[callerID] {
					visited[callerID] = true
					if caller := cg.Nodes[callerID]; caller != nil {
						result = append(result, caller)
						nextQueue = append(nextQueue, callerID)
					}
				}
			}
		}
		queue = nextQueue
		depth++
	}

	return result
}

// NodesInFile returns all function nodes defined in a given file.
func (cg *CallGraph) NodesInFile(filePath string) []*FuncNode {
	var nodes []*FuncNode
	for _, node := range cg.Nodes {
		if node.FilePath == filePath {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// RemoveFile removes all nodes from a file and cleans up edges.
func (cg *CallGraph) RemoveFile(filePath string) {
	for _, node := range cg.NodesInFile(filePath) {
		// Clean up edges pointing to this node
		for _, callerID := range node.CalledBy {
			if caller := cg.Nodes[callerID]; caller != nil {
				caller.Calls = removeStr(caller.Calls, node.ID)
			}
		}
		for _, calleeID := range node.Calls {
			if callee := cg.Nodes[calleeID]; callee != nil {
				callee.CalledBy = removeStr(callee.CalledBy, node.ID)
			}
		}
		delete(cg.Nodes, node.ID)
	}
}

// SignatureChanged checks if a function's taint signature has changed
// compared to a previous signature.
func SignatureChanged(old, new TaintSignature) bool {
	if old.IsPure != new.IsPure {
		return true
	}
	if len(old.TaintedParams) != len(new.TaintedParams) {
		return true
	}
	if len(old.TaintedReturns) != len(new.TaintedReturns) {
		return true
	}
	if len(old.SinkCalls) != len(new.SinkCalls) {
		return true
	}
	// Deep compare tainted params
	for k, v := range old.TaintedParams {
		nv, ok := new.TaintedParams[k]
		if !ok || len(v) != len(nv) {
			return true
		}
	}
	for k, v := range old.TaintedReturns {
		nv, ok := new.TaintedReturns[k]
		if !ok || len(v) != len(nv) {
			return true
		}
	}
	return false
}

// Stats returns summary statistics about the call graph.
type GraphStats struct {
	TotalFunctions  int `json:"total_functions"`
	TotalEdges      int `json:"total_edges"`
	FilesTracked    int `json:"files_tracked"`
	TaintedFuncs    int `json:"tainted_functions"`
	MaxCallDepth    int `json:"max_call_depth"`
}

func (cg *CallGraph) Stats() GraphStats {
	files := make(map[string]bool)
	totalEdges := 0
	tainted := 0

	for _, node := range cg.Nodes {
		files[node.FilePath] = true
		totalEdges += len(node.Calls)
		if len(node.TaintSig.TaintedParams) > 0 || len(node.TaintSig.SinkCalls) > 0 {
			tainted++
		}
	}

	return GraphStats{
		TotalFunctions: len(cg.Nodes),
		TotalEdges:     totalEdges,
		FilesTracked:   len(files),
		TaintedFuncs:   tainted,
	}
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func removeStr(ss []string, s string) []string {
	out := make([]string, 0, len(ss))
	for _, v := range ss {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}
