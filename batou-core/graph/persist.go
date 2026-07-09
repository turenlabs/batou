package graph

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gofrs/flock"
)

// GraphPath returns the path to the graph file for a project.
func GraphPath(projectRoot string) string {
	return filepath.Join(projectRoot, ".batou", "callgraph.json")
}

// defaultLockPath returns the path to the lockfile used by the default
// SaveGraph (relative to projectRoot). SaveGraphAt uses a lockfile co-located
// with the explicit graph file instead, so the path here is only consulted
// by SaveGraph for backwards compatibility with the original layout.
func defaultLockPath(projectRoot string) string {
	return filepath.Join(projectRoot, ".batou", "callgraph.lock")
}

// LoadGraph reads the call graph from disk (.batou/callgraph.json in project root).
// If no graph exists or the session ID doesn't match, returns a new empty graph.
func LoadGraph(projectRoot, sessionID string) (*CallGraph, error) {
	return LoadGraphAt(GraphPath(projectRoot), projectRoot, sessionID)
}

// LoadGraphAt reads the call graph from an explicit file path. Behaves like
// LoadGraph but lets callers (e.g. `batou scan --callgraph PATH`) redirect
// the load to a non-default location. projectRoot is recorded on any
// freshly-created graph so subsequent saves know where the analyzer thinks
// the project root is, independent of where the graph file lives.
func LoadGraphAt(graphFile, projectRoot, sessionID string) (*CallGraph, error) {
	cg, err := readGraphFile(graphFile)
	if err != nil {
		return nil, err
	}
	if cg == nil {
		// Missing or corrupted graph file — start fresh.
		return NewCallGraph(projectRoot, sessionID), nil
	}

	// If the session ID doesn't match, the graph is stale — start fresh.
	if cg.SessionID != sessionID {
		return NewCallGraph(projectRoot, sessionID), nil
	}

	return cg, nil
}

// DefaultMaxGraphFileBytes is the largest persisted graph file any load
// path (including `batou scan`'s warm-start) will read into memory. The
// parsed CallGraph structure is ~3-4x the file size, so an unbounded read
// of an attacker-supplied .batou/callgraph.json shipped in a repository
// could OOM the scanner (a multi-GB file → tens of GB of heap). This is a
// pure denial-of-service ceiling, set far above any legitimate graph
// (Gitea's real-world graph is ~63MB): a file over the cap is treated as
// absent so the scan simply rebuilds from scratch rather than warm-starting.
// Override with BATOU_MAX_GRAPH_MB (whole megabytes).
//
// Note the hook lane has its OWN, much smaller adoption cap
// (DefaultMaxHookAdoptBytes, 32MB) applied in LoadGraphForHookAt before
// readGraphFile is ever reached, so this ceiling only bites the scan lane
// and any direct LoadGraph/LoadGraphAt caller.
const DefaultMaxGraphFileBytes = 1024 * 1024 * 1024

// maxGraphFileBytes returns the read ceiling, honoring the
// BATOU_MAX_GRAPH_MB environment override (whole megabytes).
func maxGraphFileBytes() int64 {
	if v := os.Getenv("BATOU_MAX_GRAPH_MB"); v != "" {
		if mb, err := strconv.ParseInt(v, 10, 64); err == nil && mb > 0 {
			return mb * 1024 * 1024
		}
	}
	return DefaultMaxGraphFileBytes
}

// readGraphFile reads and unmarshals a call graph file. Returns (nil, nil)
// when the file doesn't exist, is corrupted, or exceeds the size ceiling
// (callers start fresh), and a non-nil error only for real read failures.
// Maps are initialized on the returned graph so callers never see nil
// Nodes/FileTaintCaches.
//
// NOTE: this deliberately uses os.ReadFile + json.Unmarshal rather than a
// streaming json.Decoder over the file handle. A streaming decoder was
// measured (graph load_perf_test + an out-of-tree peak-HeapInuse probe on a
// real 2.3 MB graph and a 59 MB synthetic) to give NO peak-memory benefit and
// to be marginally WORSE: Go's json.Unmarshal does not copy the input buffer,
// the parsed CallGraph structure is ~3-4x the file size (so the file buffer is
// a rounding error on peak), and json.Decoder carries its own growing internal
// scratch buffer that re-creates a file-sized allocation plus token-scanner
// overhead. The real memory lever for a 60 MB+ graph is a partial/streaming
// PARSE design (build the node map without intermediate slices) or a different
// on-disk format — out of scope for the caller-cap item; see the flag in the
// PR description.
func readGraphFile(graphFile string) (*CallGraph, error) {
	// Size-gate before reading so an oversized (or attacker-crafted) file is
	// never pulled into memory. Stat failure other than not-exist falls
	// through to ReadFile, which will surface the real error.
	if info, err := os.Stat(graphFile); err == nil && !info.IsDir() {
		if cap := maxGraphFileBytes(); info.Size() > cap {
			fmt.Fprintf(os.Stderr, "Batou: call graph %s is %d bytes (over the %d-byte cap); ignoring and rebuilding\n", graphFile, info.Size(), cap)
			return nil, nil
		}
	}

	data, err := os.ReadFile(graphFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading call graph: %w", err)
	}

	var cg CallGraph
	if err := json.Unmarshal(data, &cg); err != nil {
		// Corrupted graph file — treat as absent.
		return nil, nil
	}

	// Ensure maps are initialized (in case the file had null values).
	if cg.Nodes == nil {
		cg.Nodes = make(map[string]*FuncNode)
	}
	if cg.FileTaintCaches == nil {
		cg.FileTaintCaches = make(map[string]*FileTaintCache)
	}

	return &cg, nil
}

// DefaultMaxHookAdoptBytes is the largest persisted graph file the hook
// lane will load+adopt. JSON decode + re-encode of the graph happens on
// every hook invocation and measures ~10ms/MB end-to-end (Apple M5 Pro;
// Gitea's 63MB graph cost ~630ms, a 6.5MB synthetic ~47ms), so this caps
// the added write-time latency at roughly ~320ms on the largest adopted
// graph. Graphs over the cap are NOT adopted — the hook runs with a
// fresh session graph marked SkipPersist so it cannot clobber the
// scan-built file. Override with BATOU_HOOK_CROSSFILE_MAX_MB.
const DefaultMaxHookAdoptBytes = 32 * 1024 * 1024

// hookAdoptMaxBytes returns the adoption size cap, honoring the
// BATOU_HOOK_CROSSFILE_MAX_MB environment override (whole megabytes).
func hookAdoptMaxBytes() int64 {
	if v := os.Getenv("BATOU_HOOK_CROSSFILE_MAX_MB"); v != "" {
		if mb, err := strconv.ParseInt(v, 10, 64); err == nil && mb > 0 {
			return mb * 1024 * 1024
		}
	}
	return DefaultMaxHookAdoptBytes
}

// LoadGraphForHook is the write-time-hook variant of LoadGraph. The
// difference is the session-mismatch policy: when the persisted graph
// carries cross-file state built by `batou scan` (HasCrossFileState), it
// is ADOPTED as a project-scoped graph instead of being discarded — this
// is what lets the hook lane see the scan-built cross-file edges and
// taint signatures. The adopted graph keeps its persisted SessionID
// (typically "" from `batou scan`) so a later scan still warm-starts
// from it.
//
// Graphs WITHOUT cross-file state keep the original session semantics:
// a session mismatch starts fresh, exactly like LoadGraph.
//
// When a graph file exists but exceeds the adoption size cap, a fresh
// session graph is returned with SkipPersist set so the hook's save
// path cannot clobber the (presumed scan-built) on-disk state.
func LoadGraphForHook(projectRoot, sessionID string) (*CallGraph, error) {
	return LoadGraphForHookAt(GraphPath(projectRoot), projectRoot, sessionID)
}

// LoadGraphForHookAt is LoadGraphForHook with an explicit graph file path
// (the CallgraphPathOverride case).
func LoadGraphForHookAt(graphFile, projectRoot, sessionID string) (*CallGraph, error) {
	if info, err := os.Stat(graphFile); err == nil && !info.IsDir() && info.Size() > hookAdoptMaxBytes() {
		cg := NewCallGraph(projectRoot, sessionID)
		cg.SkipPersist = true
		return cg, nil
	}

	cg, err := readGraphFile(graphFile)
	if err != nil {
		return nil, err
	}
	if cg == nil {
		return NewCallGraph(projectRoot, sessionID), nil
	}
	if cg.SessionID == sessionID {
		return cg, nil
	}
	if cg.HasCrossFileState() {
		// Scan-built project graph: adopt across sessions. SessionID is
		// intentionally left as persisted (see doc comment).
		return cg, nil
	}
	// Hook-session graph from another session — original semantics.
	return NewCallGraph(projectRoot, sessionID), nil
}

// SaveGraph writes the call graph to disk using atomic write (temp file + rename)
// to prevent corruption. Creates the .batou/ directory if needed.
//
// Each call uses a uniquely-named temp file (via os.CreateTemp) rather than a
// shared "<graphFile>.tmp" path. The previous shared-path scheme could race
// across concurrent SaveGraph calls in the same process (e.g. the parallel
// workers in `batou scan`): goroutine A's rename would consume the shared
// tmp before goroutine B got there, leaving B's rename with "no such file
// or directory" plus a follow-on cleanup error on the same missing tmp.
// Unique temp names eliminate the race entirely without relying on the
// cross-process flock to also serialize in-process goroutines.
func SaveGraph(cg *CallGraph) error {
	return saveGraph(cg, GraphPath(cg.ProjectRoot), defaultLockPath(cg.ProjectRoot))
}

// SaveGraphAt writes the call graph to an explicit file path. Behaves like
// SaveGraph but lets callers (e.g. `batou scan --callgraph PATH`) redirect
// the save to a non-default location. The lock file is co-located with the
// graph file (suffix ".lock") so concurrent writers to the same explicit
// path still coordinate.
func SaveGraphAt(cg *CallGraph, graphFile string) error {
	return saveGraph(cg, graphFile, graphFile+".lock")
}

func saveGraph(cg *CallGraph, graphFile, lf string) error {
	dir := filepath.Dir(graphFile)

	// Ensure parent directory exists. If we can't create it (e.g. read-only
	// filesystem), surface one clear error and let the caller decide what to
	// do — better than letting downstream WriteFile / Rename failures cascade
	// into noise.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating graph directory %s: %w", dir, err)
	}

	// Acquire a cross-platform advisory lock (flock on Unix, LockFileEx on
	// Windows) via gofrs/flock so Batou can run on Windows without syscall
	// compatibility shims. The lock is primarily for cross-process
	// coordination; in-process safety comes from the unique temp file path
	// created below.
	if err := os.MkdirAll(filepath.Dir(lf), 0o755); err != nil {
		return fmt.Errorf("creating lock dir: %w", err)
	}
	lock := flock.New(lf)
	locked, err := tryLockWithTimeout(lock, 30*time.Second)
	if err != nil {
		return fmt.Errorf("acquiring lock: %w", err)
	}
	if !locked {
		return fmt.Errorf("acquiring lock: timeout after 30s")
	}
	defer releaseLock(lock)

	// Compact (non-indented) JSON: .batou/callgraph.json is a machine-managed
	// cache, not a human-edited file. In hook mode the graph is loaded and
	// re-saved on every write, and JSON encode/decode dominates that latency
	// (~10ms/MB), so dropping the ~25-40% of bytes that indentation adds cuts
	// both the marshal here and every subsequent readGraphFile/unmarshal.
	// json.Unmarshal reads compact and indented identically, so pre-existing
	// indented graphs on disk still load fine.
	data, err := json.Marshal(cg)
	if err != nil {
		return fmt.Errorf("marshaling call graph: %w", err)
	}

	// Atomic write: create a uniquely-named temp file in the same directory
	// as the final graph (so the rename stays on the same filesystem and is
	// atomic), write the data, then rename. The unique name (via
	// os.CreateTemp's "*" placeholder) keeps concurrent SaveGraph callers in
	// the same process from clobbering one another's temp files.
	tmp, err := os.CreateTemp(dir, "callgraph.*.json.tmp")
	if err != nil {
		return fmt.Errorf("creating temp graph file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup of the temp file if anything below fails. We only
	// surface a warning when the cleanup error is something other than
	// fs.ErrNotExist — in the success path, Rename consumed the temp and a
	// subsequent Remove that returns ENOENT is expected.
	cleanedUp := false
	defer func() {
		if cleanedUp {
			return
		}
		if rmErr := os.Remove(tmpName); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "Batou: graph temp cleanup: %v\n", rmErr)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temp graph file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp graph file: %w", err)
	}

	if err := os.Rename(tmpName, graphFile); err != nil {
		return fmt.Errorf("renaming temp graph file: %w", err)
	}
	cleanedUp = true

	return nil
}

// tryLockWithTimeout acquires an exclusive flock with retry until the
// deadline. gofrs/flock uses flock(2) on Unix and LockFileEx on Windows
// so this works cross-platform. Advisory locks are released automatically
// by the OS if the process dies, eliminating the stale-lock edge case
// the previous O_EXCL scheme had to handle manually.
func tryLockWithTimeout(lock *flock.Flock, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		locked, err := lock.TryLock()
		if err != nil {
			return false, err
		}
		if locked {
			return true, nil
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// releaseLock releases the advisory lock and removes the lockfile.
func releaseLock(lock *flock.Flock) {
	if lock == nil {
		return
	}
	path := lock.Path()
	if err := lock.Unlock(); err != nil {
		fmt.Fprintf(os.Stderr, "Batou: graph lock release: %v\n", err)
	}
	// Best-effort removal — the lockfile itself is harmless if it persists.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Batou: graph lock cleanup: %v\n", err)
	}
}
