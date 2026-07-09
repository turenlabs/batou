package dirscan

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	// Pull in the rule + taint catalogs so the full scanner pipeline finds
	// the Spring @RequestParam source and the MyBatis @Select ${} sink. The
	// Java MyBatis interproc sink itself lives in the graph package (compiled
	// into the binary unconditionally), but the per-file Java source/sink
	// catalogs and the interproc rule must be linked for the end-to-end flow.
	_ "github.com/turenlabs/batou-core/analyzer/javaast"
	_ "github.com/turenlabs/batou-core/scanner"
	_ "github.com/turenlabs/batou-core/taint/languages"
	_ "github.com/turenlabs/batou-core/taintrule"
	_ "github.com/turenlabs/batou-rules/rules/injection"
	_ "github.com/turenlabs/batou-rules/rules/java"
	_ "github.com/turenlabs/batou-rules/rules/validation"
)

// writeJavaMyBatisProject writes a minimal Maven-layout Spring/MyBatis
// project under root: a @RestController whose @RequestParam flows into an
// @Autowired @Mapper interface method carrying the given @Select SQL. The
// package is deliberately NOT "com.example" / under any /test/ dir so
// fpfilter.IsTestFile does not cap the finding's confidence (see the
// CRITICAL gotcha in the PR brief).
func writeJavaMyBatisProject(t *testing.T, root, selectSQL string) {
	t.Helper()
	pkgDir := filepath.Join(root, "src", "main", "java", "com", "acme", "shop")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	controller := `package com.acme.shop;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import java.util.List;

@RestController
public class UserController {

    @Autowired
    private UserMapper userMapper;

    @GetMapping("/users")
    public List<User> listUsers(@RequestParam String sort) {
        return userMapper.listBySort(sort);
    }
}
`
	mapper := `package com.acme.shop;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import java.util.List;

@Mapper
public interface UserMapper {

    @Select("` + selectSQL + `")
    List<User> listBySort(String sort);
}
`
	user := `package com.acme.shop;

public class User {
    public Long id;
    public String name;
}
`
	mustWrite(t, filepath.Join(pkgDir, "UserController.java"), controller)
	mustWrite(t, filepath.Join(pkgDir, "UserMapper.java"), mapper)
	mustWrite(t, filepath.Join(pkgDir, "User.java"), user)
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// runDirscanForCWE89 drives the full `batou scan DIR` pipeline (per-file
// scanner.Scan + shared callgraph + cross-file resolve/propagate/walk +
// JSONL emit + persistence) against root, persisting the callgraph at
// cgPath so a subsequent call with the same cgPath exercises the
// load-from-disk WARM path. Returns whether any emitted JSONL line is a
// cross-file CWE-89 interproc finding on a non-test path.
//
// The scan is run from an isolated temp working directory: dirscan's
// loadSharedCallGraph derives the project root from os.Getwd(), and the
// scanner uses a cwd-relative .batou/ for any non-overridden state. Running
// from a throwaway cwd keeps the test hermetic — a stale .batou/callgraph.json
// in the repo root must never feed into (or be clobbered by) this test.
func runDirscanForCWE89(t *testing.T, root, cgPath string) (bool, string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(prev) }()

	var out bytes.Buffer
	err = Run(context.Background(), Options{
		Root:          root,
		Exts:          []string{".java"},
		Out:           &out,
		ErrOut:        io.Discard,
		CallgraphPath: cgPath,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	sawCWE89 := false
	dec := json.NewDecoder(strings.NewReader(out.String()))
	for {
		var rec map[string]interface{}
		if err := dec.Decode(&rec); err != nil {
			break
		}
		if rec["cwe"] != "CWE-89" {
			continue
		}
		// The finding must be the cross-file interproc one and must NOT be
		// capped as a test-file finding (that cap was the original
		// false-negative dressed up as a different bug).
		if rec["is_cross_file"] == true && rec["is_test_file"] != true {
			sawCWE89 = true
		}
	}
	return sawCWE89, out.String()
}

// TestRun_JavaMyBatisDollarInterproc_ColdAndWarm is the end-to-end guard for
// the Spring-interface → MyBatis interproc flow in the REAL dirscan
// pipeline (NOT a bare graph-function call). It reproduces the regression
// that a unit-test-only fix missed: the COLD scan fires, but the WARM
// rescan — where the callgraph is reloaded from disk and every file is
// content-hash-unchanged — used to report callee-sink=0 and emit nothing,
// because UpdateFileWithAST fell back to the generic regex builder and
// clobbered the class-qualified Java nodes (dropping the MyBatis sink).
//
// We run the pipeline twice against the same persisted callgraph and
// require a CWE-89 finding BOTH times.
func TestRun_JavaMyBatisDollarInterproc_ColdAndWarm(t *testing.T) {
	root := t.TempDir()
	// `${sort}` is a MyBatis string-substitution sink → SQL injection.
	writeJavaMyBatisProject(t, root, "SELECT * FROM users ORDER BY ${sort}")
	cgPath := filepath.Join(t.TempDir(), "callgraph.json")

	cold, coldOut := runDirscanForCWE89(t, root, cgPath)
	if !cold {
		t.Fatalf("COLD scan: expected a cross-file CWE-89 interproc finding; output:\n%s", coldOut)
	}

	warm, warmOut := runDirscanForCWE89(t, root, cgPath)
	if !warm {
		t.Fatalf("WARM rescan (callgraph reloaded from disk): expected the cross-file "+
			"CWE-89 finding to STILL fire — it regressed to 0, which is the exact "+
			"generic-builder-clobber bug this fix addresses. output:\n%s", warmOut)
	}
}

// TestRun_JavaMyBatisParameterized_NoFinding is the negative control: the
// `#{sort}` parameterised (prepared-statement) binding is SAFE and must
// emit NO CWE-89 finding, on both the cold scan and the warm rescan.
func TestRun_JavaMyBatisParameterized_NoFinding(t *testing.T) {
	root := t.TempDir()
	// `#{sort}` is a parameterised bind — safe, MUST NOT fire.
	writeJavaMyBatisProject(t, root, "SELECT * FROM users WHERE name = #{sort}")
	cgPath := filepath.Join(t.TempDir(), "callgraph.json")

	cold, coldOut := runDirscanForCWE89(t, root, cgPath)
	if cold {
		t.Fatalf("COLD scan: parameterised #{} mapper must NOT emit CWE-89; output:\n%s", coldOut)
	}
	warm, warmOut := runDirscanForCWE89(t, root, cgPath)
	if warm {
		t.Fatalf("WARM rescan: parameterised #{} mapper must NOT emit CWE-89; output:\n%s", warmOut)
	}
}
