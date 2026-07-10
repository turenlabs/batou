package graph

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestKotlinBuilder_TopLevelFunction: a top-level free function is emitted
// via emitKotlinFunc with the file's package as the outermost prefix, and
// its RawCalls capture bare + receiver-qualified call expressions.
func TestKotlinBuilder_TopLevelFunction(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "handlers.kt")
	src := `package com.app

fun sanitize(s: String): String = s.trim()

fun handle(input: String): String {
    val cleaned = sanitize(input)
    return repo.save(cleaned)
}
`
	UpdateFile(cg, filePath, src, rules.LangKotlin)

	if n := cg.GetNode(filePath + ":com.app.sanitize"); n == nil {
		ids := nodeIDsInFile(cg, filePath)
		t.Fatalf("com.app.sanitize node not emitted; have %v", ids)
	}
	handle := cg.GetNode(filePath + ":com.app.handle")
	if handle == nil {
		t.Fatal("com.app.handle node not emitted")
	}
	if !containsStr(handle.RawCalls, "sanitize") {
		t.Errorf("handle.RawCalls missing 'sanitize' (got %v)", handle.RawCalls)
	}
	if !containsStr(handle.RawCalls, "repo.save") {
		t.Errorf("handle.RawCalls missing 'repo.save' (got %v)", handle.RawCalls)
	}
	// Same-file suffix edge: handle() calls sanitize(), whose node name
	// carries the package prefix — the builder wires the edge by suffix.
	if !containsStr(handle.Calls, filePath+":com.app.sanitize") {
		t.Errorf("handle.Calls missing same-file edge to sanitize (got %v)", handle.Calls)
	}
}

// TestKotlinBuilder_TopLevelFunction_NoPackage: without a `package`
// header, the free function keeps its bare name (empty prefix path of
// emitKotlinFunc).
func TestKotlinBuilder_TopLevelFunction_NoPackage(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "util.kt")
	src := "fun getName(): String = \"n\"\n"
	UpdateFile(cg, filePath, src, rules.LangKotlin)

	if n := cg.GetNode(filePath + ":getName"); n == nil {
		t.Errorf("bare getName node not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
}

// TestKotlinBuilder_OverloadDisambiguation: two same-named overloads in
// one class must NOT merge onto a single node — the second gets a
// "#<arity>@<line>" suffix (kotlinFuncArity supplies the arity), so each
// overload's body (and RawCalls) stays attributed to its own node.
func TestKotlinBuilder_OverloadDisambiguation(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Service.kt")
	src := `package com.app

class Service {
    fun run(cmd: String) {
        exec(cmd)
    }
    fun run(cmd: String, retries: Int) {
        logger.info(cmd)
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangKotlin)

	clean := cg.GetNode(filePath + ":com.app.Service.run")
	if clean == nil {
		t.Fatalf("first overload (clean name) not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
	var suffixed *FuncNode
	for _, n := range cg.NodesInFile(filePath) {
		if strings.HasPrefix(n.Name, "com.app.Service.run#") {
			suffixed = n
			break
		}
	}
	if suffixed == nil {
		t.Fatalf("second overload not disambiguated; have %v", nodeIDsInFile(cg, filePath))
	}
	// The arity is encoded between '#' and '@': the 2-parameter overload
	// collided second, so the suffix must carry arity 2.
	if !strings.Contains(suffixed.Name, "#2@") {
		t.Errorf("overload suffix = %q, want arity marker #2@<line> (kotlinFuncArity)", suffixed.Name)
	}
	// Bodies must not have merged: the clean node owns exec, the
	// suffixed node owns logger.info.
	if !containsStr(clean.RawCalls, "exec") {
		t.Errorf("first overload RawCalls missing 'exec' (got %v)", clean.RawCalls)
	}
	if containsStr(clean.RawCalls, "logger.info") {
		t.Errorf("first overload absorbed second overload's body (RawCalls %v)", clean.RawCalls)
	}
	if !containsStr(suffixed.RawCalls, "logger.info") {
		t.Errorf("second overload RawCalls missing 'logger.info' (got %v)", suffixed.RawCalls)
	}
}

// TestKotlinBuilder_ObjectAndCompanion: `object Util` members and
// companion-object members both qualify under the owning type name (the
// companion adds no extra segment), so cross-file `Type.create()` calls
// resolve directly.
func TestKotlinBuilder_ObjectAndCompanion(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Util.kt")
	src := `object Util {
    fun clean(s: String): String = s.trim()
}

class Factory {
    companion object {
        fun create(): Factory = Factory()
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangKotlin)

	if n := cg.GetNode(filePath + ":Util.clean"); n == nil {
		t.Errorf("Util.clean node not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
	if n := cg.GetNode(filePath + ":Factory.create"); n == nil {
		t.Errorf("Factory.create (companion member) not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
}

// nodeIDsInFile returns all node IDs registered for filePath — shared
// diagnostic helper for builder assertions.
func nodeIDsInFile(cg *CallGraph, filePath string) []string {
	ids := make([]string, 0)
	for _, x := range cg.NodesInFile(filePath) {
		ids = append(ids, x.ID)
	}
	return ids
}
