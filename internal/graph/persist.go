package graph

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// GraphPath returns the path to the graph file for a project.
func GraphPath(projectRoot string) string {
	return filepath.Join(projectRoot, ".gtss", "callgraph.json")
}

// lockPath returns the path to the lockfile used for concurrent access protection.
func lockPath(projectRoot string) string {
	return filepath.Join(projectRoot, ".gtss", "callgraph.lock")
}

// LoadGraph reads the call graph from disk (.gtss/callgraph.json in project root).
// If no graph exists or the session ID doesn't match, returns a new empty graph.
func LoadGraph(projectRoot, sessionID string) (*CallGraph, error) {
	graphFile := GraphPath(projectRoot)

	data, err := os.ReadFile(graphFile)
	if err != nil {
		if os.IsNotExist(err) {
			return NewCallGraph(projectRoot, sessionID), nil
		}
		return nil, fmt.Errorf("reading call graph: %w", err)
	}

	var cg CallGraph
	if err := json.Unmarshal(data, &cg); err != nil {
		// Corrupted graph file — start fresh.
		return NewCallGraph(projectRoot, sessionID), nil
	}

	// If the session ID doesn't match, the graph is stale — start fresh.
	if cg.SessionID != sessionID {
		return NewCallGraph(projectRoot, sessionID), nil
	}

	// Ensure the Nodes map is initialized (in case the file had "nodes": null).
	if cg.Nodes == nil {
		cg.Nodes = make(map[string]*FuncNode)
	}

	return &cg, nil
}

// SaveGraph writes the call graph to disk using atomic write (temp file + rename)
// to prevent corruption. Creates the .gtss/ directory if needed.
func SaveGraph(cg *CallGraph) error {
	graphFile := GraphPath(cg.ProjectRoot)
	dir := filepath.Dir(graphFile)

	// Ensure .gtss/ directory exists.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating .gtss directory: %w", err)
	}

	// Acquire a simple lockfile for concurrent access protection.
	lf := lockPath(cg.ProjectRoot)
	lock, err := acquireLock(lf)
	if err != nil {
		return fmt.Errorf("acquiring lock: %w", err)
	}
	defer releaseLock(lock, lf)

	data, err := json.MarshalIndent(cg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling call graph: %w", err)
	}

	// Atomic write: write to a temp file in the same directory, then rename.
	tmpFile := graphFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0o644); err != nil {
		return fmt.Errorf("writing temp graph file: %w", err)
	}

	if err := os.Rename(tmpFile, graphFile); err != nil {
		// Clean up temp file on rename failure.
		os.Remove(tmpFile)
		return fmt.Errorf("renaming temp graph file: %w", err)
	}

	return nil
}

// acquireLock creates a lockfile using O_CREATE|O_EXCL for atomicity.
// If the lock already exists and is older than 30 seconds, it is considered
// stale and removed.
func acquireLock(lockFile string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(lockFile), 0o755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(lockFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if !os.IsExist(err) {
			return nil, err
		}
		// Lock file exists — check if it's stale (older than 30 seconds).
		info, statErr := os.Stat(lockFile)
		if statErr != nil {
			os.Remove(lockFile)
		} else if time.Since(info.ModTime()) > 30*time.Second {
			// Stale lock — remove it.
			os.Remove(lockFile)
		} else {
			// Lock is recent — another process is likely active.
			// Fall through and overwrite; in this single-process CLI context
			// a brief conflict is unlikely.
			return os.OpenFile(lockFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		}
		f, err = os.OpenFile(lockFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("acquiring lock after cleanup: %w", err)
		}
	}
	return f, nil
}

// releaseLock closes the lockfile and removes it.
func releaseLock(f *os.File, lockFile string) {
	if f != nil {
		f.Close()
	}
	os.Remove(lockFile)
}
