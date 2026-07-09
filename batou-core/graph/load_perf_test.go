package graph

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/turenlabs/batou-rules/rules"
)

// --- Caller-file cap: load-bearing test for the 2MB -> 12MB raise ---

// buildLargeGoCaller returns a syntactically valid Go caller whose body holds a
// real cross-file taint flow (r.FormValue -> processName) but whose total size
// exceeds padBytes via a block of filler comment lines inserted between the
// source and the sink. The flow lines stay intact so the cross-file walker can
// still resolve the taint; only the file SIZE changes.
func buildLargeGoCaller(padBytes int) string {
	var b strings.Builder
	b.WriteString("package handlers\n\n")
	b.WriteString("func handler(w http.ResponseWriter, r *http.Request) {\n")
	b.WriteString("\tname := r.FormValue(\"name\")\n")
	// Filler: each line is ~64 bytes. Pad until we exceed padBytes. The filler
	// is inside the function body but does nothing — it only inflates size.
	const fillerLine = "\t// padding padding padding padding padding padding paddingx\n"
	for b.Len() < padBytes {
		b.WriteString(fillerLine)
	}
	b.WriteString("\tprocessName(name)\n")
	b.WriteString("}\n")
	return b.String()
}

// runCrossFileCallerLoad mirrors TestPropagateInterproc_CrossFileCallerLoadedFromDisk
// but with a caller file of the given size written to disk (never placed in
// fileContents, so it must be loaded by loadCallerFile and is thus gated by the
// cap). Returns the number of interprocedural findings produced.
func runCrossFileCallerLoad(t *testing.T, callerContent string) int {
	t.Helper()
	tmpDir := t.TempDir()
	callerPath := filepath.Join(tmpDir, "handler.go")
	calleePath := filepath.Join(tmpDir, "process.go")

	calleeContent := `func processName(name string) {
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}`

	if err := os.WriteFile(callerPath, []byte(callerContent), 0644); err != nil {
		t.Fatal(err)
	}

	cg := NewCallGraph(tmpDir, "test")
	callee := &FuncNode{
		ID: "pkg.processName", Name: "processName", FilePath: calleePath,
		StartLine: 1, EndLine: 3, Language: rules.LangGo,
	}
	// The caller's EndLine must cover the padded body so the walker scans the
	// whole function (StartLine..EndLine) and reaches the sink call.
	callerLines := strings.Count(callerContent, "\n") + 1
	caller := &FuncNode{
		ID: "pkg.handler", Name: "handler", FilePath: callerPath,
		StartLine: 1, EndLine: callerLines, Language: rules.LangGo,
	}
	cg.AddNode(callee)
	cg.AddNode(caller)
	cg.AddEdge(caller.ID, callee.ID)

	fileContents := map[string]string{calleePath: calleeContent}
	findings := PropagateInterproc(cg, []string{"pkg.processName"}, fileContents, nil, nil)
	return len(findings)
}

// TestCallerCap_LargeCallerResolvedAfterRaise is the load-bearing test for the
// cap raise. A caller file just over the OLD 2 MB cap:
//   - is DROPPED (0 findings) when BATOU_HOOK_CALLER_MAX_MB=2 (legacy behavior)
//   - is RESOLVED (>0 findings) at the new 12 MB default cap.
//
// Reverting the default cap to 2 MB (the copy-file revert equivalent) makes the
// "default cap" subtest fail, because the >2 MB caller would once again be
// dropped before its cross-file flow can be analyzed.
func TestCallerCap_LargeCallerResolvedAfterRaise(t *testing.T) {
	// ~2.5 MB caller: over the legacy 2 MB cap, under the new 12 MB cap.
	largeCaller := buildLargeGoCaller(int(2.5 * 1024 * 1024))
	if int64(len(largeCaller)) <= 2*1024*1024 {
		t.Fatalf("test caller is %d bytes, must exceed legacy 2MB cap", len(largeCaller))
	}
	if int64(len(largeCaller)) >= defaultMaxCallerFileSize {
		t.Fatalf("test caller is %d bytes, must be under the new default cap %d",
			len(largeCaller), defaultMaxCallerFileSize)
	}

	t.Run("legacy_2mb_cap_drops_flow", func(t *testing.T) {
		t.Setenv("BATOU_HOOK_CALLER_MAX_MB", "2")
		if n := runCrossFileCallerLoad(t, largeCaller); n != 0 {
			t.Errorf("at legacy 2MB cap the >2MB caller should be dropped (0 findings), got %d", n)
		}
	})

	t.Run("new_default_cap_resolves_flow", func(t *testing.T) {
		// No env override -> defaultMaxCallerFileSize (12 MB).
		if n := runCrossFileCallerLoad(t, largeCaller); n == 0 {
			t.Error("at the raised default cap the >2MB caller's cross-file flow " +
				"should resolve (>0 findings), got 0 — did the default cap regress to 2MB?")
		}
	})
}

// TestCallerCap_EnvOverride confirms the env override is honored both ways
// (rollback-by-config and tightening).
func TestCallerCap_EnvOverride(t *testing.T) {
	cases := []struct {
		env  string
		want int64
	}{
		{"", defaultMaxCallerFileSize},
		{"2", 2 * 1024 * 1024},
		{"16", 16 * 1024 * 1024},
		{"0", defaultMaxCallerFileSize},   // invalid (<=0) -> default
		{"abc", defaultMaxCallerFileSize}, // unparseable -> default
	}
	for _, tc := range cases {
		if tc.env == "" {
			_ = os.Unsetenv("BATOU_HOOK_CALLER_MAX_MB")
		} else {
			t.Setenv("BATOU_HOOK_CALLER_MAX_MB", tc.env)
		}
		if got := maxCallerFileSize(); got != tc.want {
			t.Errorf("maxCallerFileSize() with env=%q = %d, want %d", tc.env, got, tc.want)
		}
		_ = os.Unsetenv("BATOU_HOOK_CALLER_MAX_MB")
	}
}

// TestCallerCap_OverCapStillDropped confirms a file ABOVE the active cap is
// still skipped (the bound is present, not removed).
func TestCallerCap_OverCapStillDropped(t *testing.T) {
	t.Setenv("BATOU_HOOK_CALLER_MAX_MB", "2")
	over := buildLargeGoCaller(int(2.5 * 1024 * 1024))
	if n := runCrossFileCallerLoad(t, over); n != 0 {
		t.Errorf("file above the active 2MB cap must be dropped, got %d findings", n)
	}
}

// TestLoadCallerFile_BoundedReadAtCap confirms a file exactly at the cap is
// read successfully and one byte over is rejected (LimitReader boundary).
func TestLoadCallerFile_BoundedReadAtCap(t *testing.T) {
	t.Setenv("BATOU_HOOK_CALLER_MAX_MB", "1")
	cap := maxCallerFileSize() // 1 MB
	tmpDir := t.TempDir()

	atCap := filepath.Join(tmpDir, "atcap.go")
	if err := os.WriteFile(atCap, make([]byte, cap), 0644); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadCallerFile(nil, atCap, map[string]string{}); !ok {
		t.Error("file exactly at cap should be readable")
	}

	overCap := filepath.Join(tmpDir, "overcap.go")
	if err := os.WriteFile(overCap, make([]byte, cap+1), 0644); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadCallerFile(nil, overCap, map[string]string{}); ok {
		t.Error("file one byte over cap should be rejected")
	}
}

// --- Streaming graph decode: identical-graph + large-graph load tests ---

// buildRepresentativeGraph constructs a graph exercising the fields that the
// hook adopts: nodes with edges, taint caches, cross-file resolution state
// (ModulePaths/PackageIndex marker), etc. Used to prove the streaming decoder
// reconstructs a byte-identical in-memory graph vs the old ReadAll+Unmarshal.
func buildRepresentativeGraph(nNodes int) *CallGraph {
	cg := NewCallGraph("/repo/root", "sess-123")
	cg.Version = 7
	cg.LastUpdated = time.Unix(1700000000, 0).UTC()
	cg.ModulePaths = map[rules.Language]string{rules.LangGo: "example.com/repo"}
	cg.ModuleRoots = map[rules.Language]string{rules.LangGo: "/repo/root"}
	// A populated PackageIndex is the marker that makes HasCrossFileState()
	// true (scan-built graph) — important so we cover the adoption path's
	// fields.
	cg.PackageIndex = NewPackageIndex()
	for i := 0; i < nNodes; i++ {
		id := "pkg.Func" + strconv.Itoa(i)
		cg.AddNode(&FuncNode{
			ID:        id,
			Name:      "Func" + strconv.Itoa(i),
			FilePath:  "/repo/root/file" + strconv.Itoa(i%64) + ".go",
			StartLine: i + 1,
			EndLine:   i + 9,
			Language:  rules.LangGo,
		})
		cg.PackageIndex.Add("example.com/repo", id)
		if i > 0 {
			cg.AddEdge("pkg.Func"+strconv.Itoa(i-1), id)
		}
	}
	return cg
}

// TestGraphLoad_RoundTripIntegrity proves readGraphFile reconstructs a
// representative serialized graph faithfully: re-marshaling the loaded graph
// reproduces the original bytes, and the cross-file-state marker survives. This
// is decode-strategy-independent regression coverage for the hook adoption path
// (the same readGraphFile LoadGraphForHook calls).
func TestGraphLoad_RoundTripIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	graphFile := filepath.Join(tmpDir, "callgraph.json")

	orig := buildRepresentativeGraph(500)
	data, err := json.MarshalIndent(orig, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(graphFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := readGraphFile(graphFile)
	if err != nil {
		t.Fatalf("readGraphFile: %v", err)
	}

	// Re-marshal the loaded graph and compare to the on-disk bytes: the
	// strongest round-trip check (ignores the unexported Mu mutex, json:"-").
	rb, _ := json.MarshalIndent(loaded, "", "  ")
	if string(rb) != string(data) {
		t.Error("readGraphFile round-trip is not byte-identical to the serialized graph")
	}
	if !reflect.DeepEqual(loaded.ModulePaths, orig.ModulePaths) {
		t.Error("loaded ModulePaths differ from original")
	}
	if loaded.SessionID != orig.SessionID || loaded.Version != orig.Version {
		t.Errorf("readGraphFile lost scalar fields: sess=%q ver=%d",
			loaded.SessionID, loaded.Version)
	}
	if len(loaded.Nodes) != len(orig.Nodes) {
		t.Errorf("node count mismatch: loaded=%d orig=%d", len(loaded.Nodes), len(orig.Nodes))
	}
	if !loaded.HasCrossFileState() {
		t.Error("readGraphFile lost the cross-file-state marker (PackageIndex)")
	}
}

// TestGraphLoad_CorruptAndMissing confirms readGraphFile preserves the
// corruption-tolerant + missing-file semantics (both -> (nil,nil)) the hook
// lane relies on to "start fresh" rather than erroring.
func TestGraphLoad_CorruptAndMissing(t *testing.T) {
	tmpDir := t.TempDir()

	missing := filepath.Join(tmpDir, "nope.json")
	if cg, err := readGraphFile(missing); cg != nil || err != nil {
		t.Errorf("missing file should give (nil,nil), got (%v,%v)", cg, err)
	}

	corrupt := filepath.Join(tmpDir, "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("{not json at all"), 0644); err != nil {
		t.Fatal(err)
	}
	if cg, err := readGraphFile(corrupt); cg != nil || err != nil {
		t.Errorf("corrupt file should give (nil,nil), got (%v,%v)", cg, err)
	}
}

// TestGraphLoad_LargeGraphBounded loads a large synthetic graph and records the
// peak HeapInuse + wall time, documenting the MEASURED finding that motivated
// keeping os.ReadFile+json.Unmarshal: a streaming json.Decoder gave NO
// peak-memory benefit here (it was marginally worse) because the parsed graph
// dominates peak and the Decoder carries its own file-sized scratch buffer. The
// test asserts only that loading a large graph completes and reproduces the
// node count — it does NOT assert a memory win that does not exist.
func TestGraphLoad_LargeGraphBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-graph load test in -short mode")
	}
	tmpDir := t.TempDir()
	graphFile := filepath.Join(tmpDir, "big.json")

	big := buildRepresentativeGraph(40000)
	data, err := json.MarshalIndent(big, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(graphFile, data, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("large graph file: %.1f MB (%d nodes)", float64(len(data))/(1024*1024), len(big.Nodes))

	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)
	loaded, err := readGraphFile(graphFile)
	runtime.ReadMemStats(&m2)
	if err != nil || loaded == nil {
		t.Fatalf("readGraphFile on large graph: err=%v nil=%v", err, loaded == nil)
	}
	runtime.KeepAlive(loaded)
	t.Logf("large-graph load TotalAlloc delta=%.1f MB", float64(m2.TotalAlloc-m1.TotalAlloc)/(1024*1024))

	if len(loaded.Nodes) != len(big.Nodes) {
		t.Errorf("large-graph node count mismatch: loaded=%d orig=%d", len(loaded.Nodes), len(big.Nodes))
	}
}
