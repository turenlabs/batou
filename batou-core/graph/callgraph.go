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
	"hash/fnv"
	"sync"
	"time"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// CallGraph is the project-wide function relationship graph.
//
// CONCURRENCY: a CallGraph may be shared across multiple goroutines
// (e.g. dirscan worker pool). Callers that mutate or iterate Nodes
// concurrently must guard the access via cg.Mu. Single-threaded uses
// (the hook-mode per-file scan, simple unit tests) can ignore the
// mutex — it's uncontended and cheap.
type CallGraph struct {
	// Mu protects the graph for concurrent mutation. Locked around
	// AddNode / AddEdge / RemoveFile / SetFileTaintCache / etc. when
	// the graph is shared across workers (dirscan SharedCallGraph mode).
	// json:"-" keeps the mutex out of the persisted file.
	Mu sync.Mutex `json:"-"`

	// SkipPersist, when true, tells the scanner's hook-mode save path NOT
	// to write this graph back to disk. Set by LoadGraphForHook when a
	// scan-built graph exists on disk but was too large to adopt within
	// the hook's latency budget — saving a fresh session graph over it
	// would destroy the scan-built cross-file state. Never serialized.
	SkipPersist bool `json:"-"`

	// Nodes maps function IDs to their metadata.
	Nodes map[string]*FuncNode `json:"nodes"`

	// FileTaintCaches maps file paths to their taint analysis cache entries.
	// When taint analysis runs on a file and finds zero flows, the cache
	// records this "negative confirmation" so that future scans can suppress
	// regex-only findings for taint-coverable CWEs without re-running taint.
	FileTaintCaches map[string]*FileTaintCache `json:"file_taint_caches,omitempty"`

	// FileFindingHistories maps file paths to their finding lifecycle summaries.
	// Updated after each scan with delta counts so the graph tracks how many
	// findings have been fixed over time per file.
	FileFindingHistories map[string]*FileFindingHistory `json:"file_finding_histories,omitempty"`

	// ProjectRoot is the project directory this graph belongs to.
	ProjectRoot string `json:"project_root"`

	// SessionID tracks which Claude session built this graph.
	SessionID string `json:"session_id"`

	// LastUpdated is when the graph was last modified.
	LastUpdated time.Time `json:"last_updated"`

	// Version for format compatibility.
	Version int `json:"version"`

	// --- Cross-file resolution (PR-A framework, populated by adapters) ---

	// ModulePaths records the project's module/package import-path
	// prefix per language as discovered by the per-language resolver
	// (see resolver.go::LanguageResolver.ProjectRoot). For a Go project
	// this is the value declared in go.mod ("code.gitea.io/gitea"); for
	// Python it's the top-level package name from pyproject.toml; etc.
	// Empty when no manifest was found or the resolver couldn't extract
	// a module path.
	ModulePaths map[rules.Language]string `json:"module_paths,omitempty"`

	// ModuleRoots maps each language to the directory containing the
	// manifest that declares ModulePaths[lang]. Used when computing a
	// file's in-project import path: subtract ModuleRoots[lang] from
	// the file's directory to get the package suffix, then prepend
	// ModulePaths[lang]. Both fields are populated together by the
	// resolver's ProjectRoot.
	ModuleRoots map[rules.Language]string `json:"module_roots,omitempty"`

	// FileModules records the per-file module assignment for repos
	// that have multiple go.mod / package.json / pyproject.toml files
	// (the Vault / Kubernetes monorepo shape). Without this map a
	// single ModulePaths[lang] is used for every file in the project,
	// which mis-classifies sub-module calls as "outside the module"
	// and loses ~80% of cross-file edges on multi-module Go repos.
	// Keyed by file path; populated by the cross-file resolution pass
	// via per-file manifest discovery.
	FileModules map[string]FileModule `json:"file_modules,omitempty"`

	// PackageIndex maps in-project package paths to the FuncNode IDs
	// declared in them. Populated by the cross-file resolution pass
	// after per-file AST extraction completes. Cleared and rebuilt on
	// every full scan so it stays in sync with the node set.
	PackageIndex *PackageIndex `json:"package_index,omitempty"`

	// FileScopes records the per-file import/package context produced
	// by LanguageResolver.ExtractScope. Cached here so the cross-file
	// pass and any future incremental rescan can reuse them without
	// re-parsing source. Keyed by file path; cleared when the file's
	// content hash changes.
	FileScopes map[string]FileScope `json:"file_scopes,omitempty"`
}

// FileModule records the module / manifest a single file belongs to.
// Used by the cross-file resolver in multi-module repos.
type FileModule struct {
	// ModulePath is the canonical import-path prefix declared in the
	// nearest manifest (e.g. "github.com/hashicorp/vault/api").
	ModulePath string `json:"module_path,omitempty"`
	// ModuleRoot is the absolute directory containing that manifest.
	ModuleRoot string `json:"module_root,omitempty"`
}

// FileTaintCache records the result of taint analysis on a file so that
// subsequent scans can use "negative taint confirmation" — if taint ran
// and found nothing, regex findings for taint-coverable CWEs are suppressed.
type FileTaintCache struct {
	// ContentHash is an FNV-1a hash of the file content. When the hash
	// changes, the cache entry is stale and taint must re-run.
	ContentHash uint64 `json:"content_hash"`

	// FlowCount is the number of taint flows found (0 = taint-clean).
	FlowCount int `json:"flow_count"`

	// ScannedAt records when this entry was last updated.
	ScannedAt time.Time `json:"scanned_at"`

	// Sig is an HMAC over (path, ContentHash, FlowCount) keyed by a
	// per-machine secret stored OUTSIDE any scanned repository (see
	// cache_trust.go). It is what lets a negative "taint-clean" verdict be
	// trusted for suppressing regex findings: a repo-shipped, attacker-crafted
	// .batou/callgraph.json cannot forge a valid Sig without the local key, so
	// its FlowCount==0 entries never suppress a real detection. Purely a
	// suppression-authority gate — an absent/invalid Sig only means "do not let
	// this entry hide findings", never "add findings", so cross-machine graph
	// sharing degrades safely (positive edges/signatures are unaffected).
	Sig string `json:"sig,omitempty"`
}

// FileFindingHistory tracks finding lifecycle metrics for a file across scans.
// This allows the call graph to serve as a single source of truth for how many
// findings have been introduced, fixed, and suppressed over time.
type FileFindingHistory struct {
	ContentHash     uint64    `json:"content_hash"`
	ActiveCount     int       `json:"active_count"`
	FixedCount      int       `json:"fixed_count"`
	SuppressedCount int       `json:"suppressed_count"`
	LastScanned     time.Time `json:"last_scanned"`
}

// UpdateFindingHistory updates the finding history for a file using the
// given delta counts from the findings store. The content hash is used
// to detect file changes.
func (cg *CallGraph) UpdateFindingHistory(filePath string, contentHash uint64, activeCount, fixedCount, suppressedCount int) {
	if cg.FileFindingHistories == nil {
		cg.FileFindingHistories = make(map[string]*FileFindingHistory)
	}

	existing := cg.FileFindingHistories[filePath]
	if existing == nil {
		existing = &FileFindingHistory{}
		cg.FileFindingHistories[filePath] = existing
	}

	existing.ContentHash = contentHash
	existing.ActiveCount = activeCount
	existing.FixedCount += fixedCount // accumulate total fixed over time
	existing.SuppressedCount = suppressedCount
	existing.LastScanned = time.Now()
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

	// ExternCalls lists out-of-project package functions this node
	// invokes, in the form `<package>.<function>` (e.g. "net/http.Get",
	// "json.Unmarshal", "fmt.Sprintf"). Populated by the cross-file
	// resolution pass when a call's import target lies outside the
	// project's ModulePaths. Useful for downstream consumers asking
	// "what external surface does this function touch?" without having
	// to re-parse the file.
	ExternCalls []string `json:"extern_calls,omitempty"`

	// UnresolvedCalls lists call expressions the resolver could not
	// pin down to either an in-project node or a known external
	// package — typically dynamic dispatch on an interface value or a
	// method on a variable whose type couldn't be inferred. Kept as
	// raw call-text so future, smarter resolvers can take another pass
	// at them without re-parsing the file.
	UnresolvedCalls []string `json:"unresolved_calls,omitempty"`

	// RawCalls preserves the raw call-expression strings extracted from
	// the function body in the form a per-language extractor emits
	// (typically "pkg.Func" or "Func" for Go). Used by the cross-file
	// resolution pass so it can re-resolve every call against the global
	// package index without re-parsing the file. Same-file resolution
	// during initial extraction still populates Calls directly; this
	// field is additive and not consumed by the same-file pass.
	RawCalls []string `json:"raw_calls,omitempty"`

	// Taint signature — the security-relevant interface of this function.
	// This is what changes when we need to re-analyze callers.
	TaintSig TaintSignature `json:"taint_sig"`

	// RoutePath / RouteMethod describe an in-repo HTTP route this node is
	// registered as the handler for. Populated by the per-language
	// builders when they recognise a route-registration shape that names
	// this node as the handler (Express `app.get("/x", h)`, Flask
	// `@app.route("/x")`, etc.). RoutePath is the normalised path literal
	// (leading slash, no query string, no trailing slash — see
	// NormalizeRoutePath). Empty on non-handler nodes.
	//
	// The cross-language service-boundary matcher
	// (linkServiceBoundaryEdges in resolve.go) keys route-handler nodes by
	// RoutePath so an OUTBOUND request site in another file/language —
	// recorded in OutboundRequests below — can be linked to the in-repo
	// handler that serves the same path, regardless of language.
	RoutePath   string `json:"route_path,omitempty"`
	RouteMethod string `json:"route_method,omitempty"`

	// OutboundRequests lists outbound HTTP request sites found in this
	// node's body that target an in-repo route path with a tainted
	// argument (e.g. JS `fetch("/api/x?q=" + req.query.q)` /
	// `axios.post("/api/x", userInput)`). Each entry carries the path
	// literal the request targets so linkServiceBoundaryEdges can match it
	// to the route handler that serves that path. Empty when the node
	// makes no tainted outbound request.
	OutboundRequests []OutboundRequest `json:"outbound_requests,omitempty"`

	// Change tracking
	ContentHash string         `json:"content_hash"` // SHA-256 of the function body
	LastScanAt  time.Time      `json:"last_scan_at"` // When this node was last analyzed
	Language    rules.Language `json:"language"`

	// Findings from intraprocedural analysis of this function
	FindingCount int `json:"finding_count"`
}

// OutboundRequest records a single outbound HTTP request site inside a
// function body that targets an in-repo route path with a tainted
// argument. Captured by the per-language builders (currently the JS/TS
// builder for fetch / axios) and consumed by the cross-language
// service-boundary matcher in resolve.go.
type OutboundRequest struct {
	// Path is the normalised in-repo route path the request targets
	// (NormalizeRoutePath applied — leading slash, query string stripped).
	Path string `json:"path"`
	// Method is the HTTP method (lower-case: "get", "post", ...). Empty
	// means "unknown / any" and matches any handler method.
	Method string `json:"method,omitempty"`
	// Line is the 1-based source line of the request call.
	Line int `json:"line"`
	// TaintedArg is the argument expression that carries user-controlled
	// data into the request (e.g. `req.query.sort`, `userInput`). Empty
	// when no tainted argument was detected — such sites are not linked.
	TaintedArg string `json:"tainted_arg,omitempty"`
	// SourceCategory classifies the taint source (e.g. "user_input").
	SourceCategory string `json:"source_category,omitempty"`
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

	// TaintedReturnPaths is the field-sensitive refinement of
	// TaintedReturns (PR3). Key is a bounded "retIdx.field.field" access
	// path off a returned value (e.g. "0.user.id" for a callee that
	// returns `{user:{id: req.query.id}, name:"x"}`); value is the taint
	// categories on that exact path. The caller composes
	// boundAccessPath(returnVar + "." + path-suffix) and fires only when
	// a tainted prefix exists — so `sink(r.user.id)` fires while
	// `sink(r.name)` stays silent. TaintedReturns (whole-return,
	// index-keyed) is kept alongside; an empty TaintedReturnPaths means
	// legacy whole-return behaviour (a loaded legacy graph unmarshals
	// this to nil and falls through to the index-keyed logic). Path keys
	// are bounded via tsflow.BoundAccessPath.
	TaintedReturnPaths map[string][]taint.SourceCategory `json:"tainted_return_paths,omitempty"`

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

	// TaintedFields records instance-field / module-global STORED-STATE
	// writes of external taint performed by this function — the producer
	// side of the cross-file stored-state channel (Tier-1).
	//
	// The canonical missed OO flow is:
	//
	//	# file A          class C: def load(self): self.q = request.args["q"]
	//	# file B (other)  class C: def run(self):  os.system(self.q)
	//
	// The two methods share no call edge, so the call-edge-driven
	// cross-file walk never connects them. Instead the writer records the
	// field key it taints here; the reader pass (WalkCrossFileStoredState)
	// joins writer→reader by enclosing class (or module) identity across
	// files and fires when the reader sinks the same field.
	//
	// Each entry is one tainted field-write. Key is the field access path
	// relative to the instance receiver (e.g. "q" for `self.q`) or the
	// bare module-global name. Populated by the per-language stored-state
	// producer pass; empty for functions with no tainted stored-state
	// write and for languages without stored-state support.
	TaintedFields []TaintedFieldWrite `json:"tainted_fields,omitempty"`

	// SanitizedPaths notes which param→sink paths pass through sanitizers.
	SanitizedPaths []SanitizedPath `json:"sanitized_paths,omitempty"`

	// IsPure is true if this function has no security-relevant side effects
	// and doesn't propagate taint (e.g., pure math, string formatting).
	IsPure bool `json:"is_pure,omitempty"`

	// Params carries position-ordered typed parameter information extracted
	// from the function declaration. Populated only for Go functions when
	// a parsed *ast.File is available; empty for legacy signatures and for
	// languages without typed-summary support.
	Params []ParamTaint `json:"params,omitempty"`

	// Returns carries position-ordered typed return information from the
	// function declaration's result list.
	Returns []ReturnTaint `json:"returns,omitempty"`

	// TypesVersion records the schema of typed metadata on this signature.
	//   0 = legacy (no Params/Returns populated)
	//   1 = typed summaries with canonical Go types
	TypesVersion int `json:"types_version,omitempty"`
}

// ParamTaint carries typed metadata for a single function parameter.
//
// Multiple ParamTaint rows MAY share one Index: a destructured binding
// `function run({cmd, safe}) {...}` produces several rows all with
// Index 0 (the single object parameter), each carrying a distinct
// FieldName so the cross-file walker can rebind the bare destructured
// name (`cmd`) to the field path it actually reads off the param object
// ("cmd"). For a plain `function run(opts)` parameter there is one row
// with an empty FieldName (whole-param = legacy).
type ParamTaint struct {
	Index          int                  `json:"index"`
	Name           string               `json:"name,omitempty"`
	Type           string               `json:"type,omitempty"`
	CanonicalType  string               `json:"canonical_type,omitempty"`
	IsSourceType   bool                 `json:"is_source_type,omitempty"`
	IsSinkType     bool                 `json:"is_sink_type,omitempty"`
	SourceCategory taint.SourceCategory `json:"source_category,omitempty"`
	SinkCategory   taint.SinkCategory   `json:"sink_category,omitempty"`

	// FieldName is the object field this row binds to when the parameter
	// is destructured (`function run({cmd}) {...}` → row with Index 0,
	// Name "cmd", FieldName "cmd"). Empty for a plain whole-object
	// parameter. Permits MULTIPLE ParamTaint rows to share one Index
	// (one per destructured field). Used by the JS cross-file walker to
	// map a bare destructured param name back to its field access path
	// for field-sensitive sink gating (PR3).
	FieldName string `json:"field_name,omitempty"`
}

// ReturnTaint carries typed metadata for a single function return value.
type ReturnTaint struct {
	Index          int                  `json:"index"`
	Name           string               `json:"name,omitempty"`
	Type           string               `json:"type,omitempty"`
	CanonicalType  string               `json:"canonical_type,omitempty"`
	IsSourceType   bool                 `json:"is_source_type,omitempty"`
	SourceCategory taint.SourceCategory `json:"source_category,omitempty"`
}

// SinkRef records a sink call inside a function.
//
// For inherited sinks lifted up by PropagateSignaturesAcrossCallgraph,
// Line points to the call site in the inheriting function (the "via X"
// hop), and OriginFile/OriginLine point to where the actual dangerous
// call physically lives. Both are zero for first-class sinks recorded
// directly by the per-file analyzer; consumers that need the leaf-sink
// location for cross-file findings should fall back to (FilePath, Line)
// of the SinkRef's owning node when OriginFile is empty.
type SinkRef struct {
	SinkCategory taint.SinkCategory `json:"category"`
	MethodName   string             `json:"method"`
	Line         int                `json:"line"`
	ArgFromParam int                `json:"arg_from_param"` // Which param flows to this sink (-1 if none)

	// ArgFieldPath is the bounded access path the sink reads OFF its
	// param — the field-sensitivity refinement of ArgFromParam (PR3).
	// For `function run(opts){ exec(opts.cmd); }` ArgFromParam is the
	// index of `opts` and ArgFieldPath is "cmd"; the cross-file walker
	// composes callerArg + "." + ArgFieldPath and gates on the caller's
	// per-field taint for that exact path, so `o.cmd = req.body.cmd`
	// fires while `o.cmd = "ls"` (only a sibling field tainted) stays
	// silent. Empty = whole-param consumption = legacy behaviour (a
	// loaded legacy graph unmarshals this to "" and falls through to the
	// index-keyed ArgFromParam logic). Bounded via tsflow.BoundAccessPath.
	ArgFieldPath string `json:"arg_field_path,omitempty"`

	// OriginFile and OriginLine record the leaf sink's physical
	// location when this SinkRef was lifted up the call graph by
	// PropagateSignaturesAcrossCallgraph. Empty/zero for direct sinks.
	OriginFile string `json:"origin_file,omitempty"`
	OriginLine int    `json:"origin_line,omitempty"`
}

// TaintedFieldWrite records one external-taint write into an instance
// field or module global — the producer record of the cross-file
// stored-state channel (see TaintSignature.TaintedFields).
type TaintedFieldWrite struct {
	// Field is the stored-state key: the field access path relative to the
	// instance receiver (`self.q` → "q") or the bare module-global name.
	Field string `json:"field"`
	// IsGlobal distinguishes a module-global write (`g = source`, true)
	// from an instance-field write (`self.q = source`, false). The reader
	// pass joins instance fields by enclosing class identity and globals by
	// module/package identity.
	IsGlobal bool `json:"is_global,omitempty"`
	// SourceCategory classifies the external taint stored (e.g.
	// "user_input").
	SourceCategory taint.SourceCategory `json:"source_category,omitempty"`
	// Line is the 1-based file-absolute line of the write.
	Line int `json:"line,omitempty"`
	// SourceText is the RHS source expression as written, for the taint
	// path step label (e.g. `request.args.get("q")`).
	SourceText string `json:"source_text,omitempty"`
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
	CallerID   string            // ID of the caller function
	CallerNode *FuncNode         // The caller's node
	CallLine   int               // Line where the call happens
	Reason     string            // Why this caller is impacted
	Severity   rules.Severity    // How serious the impact is
	TaintPath  []rules.TaintStep // Cross-file source→sink chain (may be partial: source + sink only)
}

// HasCrossFileState reports whether this graph carries the cross-file
// resolution state that only `batou scan`'s finalize pass produces
// (ResolveCrossFileEdges populates PackageIndex; the per-file hook lane
// never does). Used as the marker distinguishing a scan-built project
// graph from a hook-session graph.
func (cg *CallGraph) HasCrossFileState() bool {
	return cg != nil && cg.PackageIndex != nil && len(cg.PackageIndex.PackageToNodes) > 0
}

// NewCallGraph creates an empty call graph.
func NewCallGraph(projectRoot, sessionID string) *CallGraph {
	return &CallGraph{
		Nodes:           make(map[string]*FuncNode),
		FileTaintCaches: make(map[string]*FileTaintCache),
		ProjectRoot:     projectRoot,
		SessionID:       sessionID,
		LastUpdated:     time.Now(),
		Version:         1,
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

// FileContentHash computes an FNV-1a hash of file content for fast
// cache invalidation. FNV-1a is non-cryptographic but extremely fast
// and sufficient for change detection.
func FileContentHash(content string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(content))
	return h.Sum64()
}

// SetFileTaintCache records a taint analysis result for a file.
// Call this after taint analysis runs to enable negative confirmation
// (suppressing regex findings when taint found nothing).
func (cg *CallGraph) SetFileTaintCache(path string, contentHash uint64, flowCount int) {
	if cg.FileTaintCaches == nil {
		cg.FileTaintCaches = make(map[string]*FileTaintCache)
	}
	cg.FileTaintCaches[path] = &FileTaintCache{
		ContentHash: contentHash,
		FlowCount:   flowCount,
		ScannedAt:   time.Now(),
		// Sign with the per-machine key so this clean verdict can later be
		// trusted to suppress regex findings. A graph shipped in a repo can't
		// forge this without the local key. Empty when no key is available —
		// which simply means the entry won't be trusted for suppression.
		Sig: signFileTaintCache(path, contentHash, flowCount),
	}
}

// GetFileTaintCache returns the cached taint result for a file, or nil
// if no cache entry exists.
func (cg *CallGraph) GetFileTaintCache(path string) *FileTaintCache {
	if cg.FileTaintCaches == nil {
		return nil
	}
	return cg.FileTaintCaches[path]
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
	if len(queue) > 0 && frontierHasUnvisitedCallers(cg, queue, visited) {
		// Diagnostics only: the BFS stopped at maxDepth with unexplored
		// callers remaining — deeper transitive callers were truncated.
		capHits.depth.Add(1)
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
	// Typed-summary fields: enrichment upgrades a function even when the
	// regex/flow-derived fields are empty (e.g. a pure caller with typed
	// source params). Without this, callers that are pure-by-regex never
	// get their typed Params saved.
	if old.TypesVersion != new.TypesVersion {
		return true
	}
	if len(old.Params) != len(new.Params) {
		return true
	}
	if len(old.Returns) != len(new.Returns) {
		return true
	}
	// Value-aware sink comparison: a SAME-COUNT mutation — e.g. a callee edited
	// so an os.WriteFile FileWrite sink becomes an exec.Command sink, or a
	// sink's consumed-param index is remapped — must count as changed. A
	// length-only check judged it "unchanged", left the stale node signature in
	// place, and skipped the transitive caller re-walk, so callers stayed
	// analysed against the wrong category. SinkCalls are emitted in
	// deterministic source order. (Can only cause MORE re-analysis, which the
	// normal pipeline then filters — no FP cost.)
	for i := range old.SinkCalls {
		o, n := old.SinkCalls[i], new.SinkCalls[i]
		if o.SinkCategory != n.SinkCategory || o.ArgFromParam != n.ArgFromParam ||
			o.MethodName != n.MethodName || o.ArgFieldPath != n.ArgFieldPath {
			return true
		}
	}
	// SourceParams (direct taint-source params, e.g. *http.Request handlers)
	// was never compared — a param gaining/losing source status, or changing
	// category, is a real signature change.
	if len(old.SourceParams) != len(new.SourceParams) {
		return true
	}
	for k, v := range old.SourceParams {
		if nv, ok := new.SourceParams[k]; !ok || nv != v {
			return true
		}
	}
	// Deep compare tainted params/returns by CATEGORY VALUES, not just arity.
	for k, v := range old.TaintedParams {
		nv, ok := new.TaintedParams[k]
		if !ok || !sameCategorySet(v, nv) {
			return true
		}
	}
	for k, v := range old.TaintedReturns {
		nv, ok := new.TaintedReturns[k]
		if !ok || !sameCategorySet(v, nv) {
			return true
		}
	}
	return false
}

// sameCategorySet reports whether two taint-category slices hold the same set
// of categories (order-independent). Used by SignatureChanged so a category
// swap with an unchanged count is treated as a real signature change.
func sameCategorySet(a, b []taint.SourceCategory) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[taint.SourceCategory]int, len(a))
	for _, c := range a {
		seen[c]++
	}
	for _, c := range b {
		seen[c]--
		if seen[c] < 0 {
			return false
		}
	}
	return true
}

// Stats returns summary statistics about the call graph.
type GraphStats struct {
	TotalFunctions int `json:"total_functions"`
	TotalEdges     int `json:"total_edges"`
	FilesTracked   int `json:"files_tracked"`
	TaintedFuncs   int `json:"tainted_functions"`
	MaxCallDepth   int `json:"max_call_depth"`
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
