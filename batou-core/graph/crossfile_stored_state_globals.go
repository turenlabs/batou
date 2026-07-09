// Cross-file MODULE-GLOBAL stored-state taint (Task B, Python slice).
//
// The instance-field stored-state channel (crossfile_stored_state.go) joins a
// field writer and a field reader by enclosing CLASS identity. The MODULE-
// GLOBAL channel is the function-less analogue:
//
//	# config.py            (a config module — NO functions, NO classes)
//	API_TARGET = os.environ["UPSTREAM"]      # top-level external-source write
//
//	# worker.py            (a different file)
//	from config import API_TARGET
//	def run():
//	    os.system(API_TARGET)                # read that global -> sink
//
// The producer module (`config.py`) holds only top-level globals, so it has NO
// FuncNode in the call graph — the graph is built from functions/classes. That
// makes the producer module structurally invisible to WalkCrossFileStoredState
// (which iterates cg.Nodes). The reader-side join and the IsGlobal finding
// path are already threaded through scanReaderForStoredSinksBare /
// buildStoredStateFinding; this file wires the missing PRODUCER side.
//
// WalkCrossFilePythonGlobals takes the on-disk file list (available in the
// dirscan finalize pass) and:
//
//  1. PRODUCER: scans every .py file's MODULE TOP LEVEL (indentation 0, never
//     inside a def/class) for `X = <external catalog source>` assignments,
//     recording (producer module, global name) → write fact. Sanitized and
//     param-sourced writes are excluded exactly as the field channel excludes
//     them (a top-level statement has no parameters, so param-sourced writes
//     cannot occur — the sourceRe gate is the live discriminator).
//
//  2. CONSUMER: for every Python reader FuncNode whose FILE imports the
//     producer module AND binds the global name, scans the reader body for a
//     sink reading that global. The IMPORT ANCHOR is the FP guard: two unrelated
//     modules that both define `DEBUG` at top level never join unless the
//     reader actually `from <producer> import DEBUG` (or `import <producer>`
//     and reads `<producer>.DEBUG`). A config file that is never imported by a
//     sink-bearing reader produces no finding.
//
// Confidence stays 0.8 (the cross-file interproc tier), matching the field
// channel. Python only in this slice: it is the OWASP-benched language (recall
// measurable) and the canonical config-module shape. Extending to other
// languages needs each language's module/global-binding import semantics
// (Ruby `require` + top-level constants, JS `module.exports`/ESM named
// exports), which differ enough to defer.

package graph

import (
	"regexp"
	"sort"
	"strings"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// rePyModuleGlobalWrite matches a MODULE-TOP-LEVEL assignment `NAME = rhs`
// with ZERO leading indentation (so it is never a statement inside a def or
// class body, both of which are indented). Captures the global name and the
// RHS. Augmented-assignment (`+=`) and comparisons (`==`) are excluded by
// requiring a single `=` not preceded/followed by an operator char.
//
// PEP 8 SCREAMING_SNAKE_CASE is the convention for module constants, but real
// config modules also use lowercase (`config = ...`, `db_url = ...`), so the
// name pattern is the general identifier — the source-expression gate, not the
// casing, decides whether the write is a stored external source.
var rePyModuleGlobalWrite = regexp.MustCompile(
	`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^=].*)$`)

// pyGlobalProducer is one module-global write fact: the global name, the file
// and module it was written in, the source text and line.
type pyGlobalProducer struct {
	module     string
	name       string
	file       string
	line       int
	sourceText string
}

// WalkCrossFilePythonGlobals is the Python module-global stored-state driver.
// It runs in the dirscan finalize pass (which has the on-disk file list, the
// one place the function-less producer module is visible). pyFiles is the list
// of .py files in the scan (absolute or scan-relative paths — whatever the
// dirscan walk produced; matched against reader FuncNode.FilePath). Returns the
// synthesised findings, deduplicated by (reader file, sink line, global).
func WalkCrossFilePythonGlobals(cg *CallGraph, pyFiles []string) []rules.Finding {
	if cg == nil || len(pyFiles) == 0 {
		return nil
	}

	// PRODUCER side-table: module -> global name -> producer record.
	producers := map[string]map[string]pyGlobalProducer{}
	for _, f := range pyFiles {
		if !strings.HasSuffix(f, ".py") {
			continue
		}
		content, ok := loadCallerFile(cg, f, map[string]string{})
		if !ok || content == "" {
			continue
		}
		module := pythonModuleForFile(cg, f)
		if module == "" {
			continue
		}
		for _, w := range scanPythonModuleGlobals(content) {
			byName := producers[module]
			if byName == nil {
				byName = map[string]pyGlobalProducer{}
				producers[module] = byName
			}
			if _, exists := byName[w.name]; exists {
				continue // first tainted writer per (module, name) wins
			}
			byName[w.name] = pyGlobalProducer{
				module:     module,
				name:       w.name,
				file:       f,
				line:       w.line,
				sourceText: w.sourceText,
			}
		}
	}
	if len(producers) == 0 {
		return nil
	}

	sinkPatterns := loadPythonSinkPatterns()
	if len(sinkPatterns) == 0 {
		return nil
	}
	neutral := make([]storedStateSinkPattern, 0, len(sinkPatterns))
	for _, p := range sinkPatterns {
		neutral = append(neutral, storedStateSinkPattern{
			pattern: p.pattern, category: p.category, method: p.method,
			module: p.module, requireModule: p.requireModule,
		})
	}

	pyCfg := storedStateLangConfig{
		lang:            rules.LangPython,
		sinkNeutralises: sinkLineSanitizerNeutralises,
		commentPrefixes: []string{"#"},
	}

	var findings []rules.Finding
	seen := map[string]bool{}
	// Iterate readers deterministically.
	ids := sortedNodeIDs(cg)
	for _, id := range ids {
		reader := cg.Nodes[id]
		if reader == nil || reader.Language != rules.LangPython {
			continue
		}
		scope, ok := cg.FileScopes[reader.FilePath]
		if !ok || len(scope.Imports) == 0 {
			continue
		}
		// Which producer globals does THIS reader's file import? Build the set
		// of bound names (and their read tokens) that resolve to a producer.
		boundGlobals := resolvePyImportedGlobals(scope, producers, reader.FilePath)
		if len(boundGlobals) == 0 {
			continue
		}
		content, ok := loadCallerFile(cg, reader.FilePath, map[string]string{})
		if !ok {
			continue
		}
		body := extractFuncBody(content, reader.StartLine, reader.EndLine)
		if body == "" {
			continue
		}
		lines, offsets := joinPythonParenContinuations(body)
		// For each (read-token -> producer) binding, run the global reader scan
		// with the read token as the field key.
		for readToken, prod := range boundGlobals {
			fields := map[string]storedFieldProducer{
				readToken: {
					node:       nil,
					field:      readToken,
					sourceText: prod.sourceText,
					sourceCat:  taint.SrcExternal,
					line:       prod.line,
				},
			}
			findings = append(findings,
				scanGlobalReaderForSinks(pyCfg, prod, reader, lines, offsets, fields, neutral, seen)...,
			)
		}
	}
	return findings
}

// sortedNodeIDs returns cg.Nodes keys sorted for deterministic iteration.
func sortedNodeIDs(cg *CallGraph) []string {
	ids := make([]string, 0, len(cg.Nodes))
	for id := range cg.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// pythonModuleForFile computes the dotted module name for a producer file using
// the same arithmetic ResolveCrossFileEdges uses for reader files
// (pythonModuleKey against the per-file / global ModuleRoot). A function-less
// producer file is not in cg.FileModules, so the global ModuleRoot fallback is
// used — correct for the common single-manifest project.
func pythonModuleForFile(cg *CallGraph, filePath string) string {
	_, root := moduleForFile(cg, filePath, rules.LangPython)
	return pythonModuleKey(filePath, root, "")
}

// pyGlobalWrite is one module-top-level external-source assignment.
type pyGlobalWrite struct {
	name       string
	line       int
	sourceText string
}

// scanPythonModuleGlobals scans content's MODULE TOP LEVEL for external-source
// global writes. Only indentation-0 simple assignments are considered (a line
// inside a def/class body is indented in valid Python, so this excludes them
// structurally). Sanitized RHS and non-source RHS are dropped. A def/class
// header at column 0 starts an indented block we skip until indentation
// returns to 0.
func scanPythonModuleGlobals(content string) []pyGlobalWrite {
	lines, offsets := joinPythonParenContinuations(content)
	var out []pyGlobalWrite
	seen := map[string]bool{}
	for i, raw := range lines {
		// MODULE TOP LEVEL only: zero leading whitespace.
		if len(raw) == 0 || raw[0] == ' ' || raw[0] == '\t' {
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Skip compound-statement headers and non-assignment top-level
		// constructs — their bodies are indented and already excluded above,
		// but the header line itself must not be mistaken for an assignment.
		if isPythonBlockHeader(trimmed) {
			continue
		}
		m := rePyModuleGlobalWrite.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		name, rhs := m[1], strings.TrimSpace(m[2])
		if seen[name] {
			continue
		}
		if !pythonSourceExprRe.MatchString(rhs) {
			continue
		}
		if pythonSanitizerRe.MatchString(rhs) {
			continue
		}
		line := i + 1
		if i < len(offsets) {
			line = offsets[i] + 1
		}
		seen[name] = true
		out = append(out, pyGlobalWrite{
			name:       name,
			line:       line,
			sourceText: truncateExpr(rhs),
		})
	}
	return out
}

// rePyBlockHeader matches a top-level compound-statement header so a global
// scan does not treat `def x = ...`-looking lines or decorators as assignments.
var rePyBlockHeader = regexp.MustCompile(
	`^(?:def|class|if|elif|else|for|while|try|except|finally|with|async|@)\b`)

func isPythonBlockHeader(trimmed string) bool {
	return rePyBlockHeader.MatchString(trimmed)
}

// resolvePyImportedGlobals returns the read-token -> producer map for the
// globals THIS reader file imports from a producer module. The import anchor is
// the FP guard: a global only participates if the reader's file actually
// imports it.
//
// Two binding shapes are recognised, mirroring collectImport* in
// resolver_python.go:
//   - `from <mod> import X`  → scope.Imports["X"] == "<mod>.X"; the read token
//     is the bare bound name (possibly aliased: `from m import X as Y` binds
//     "Y" → "m.X", read token "Y").
//   - `import <mod>` / `import <mod> as A` → scope.Imports["<mod-or-alias>"]
//     == "<mod>"; the read token is "<alias>.<global>" (qualified access).
func resolvePyImportedGlobals(scope FileScope, producers map[string]map[string]pyGlobalProducer, _readerFile string) map[string]pyGlobalProducer {
	out := map[string]pyGlobalProducer{}
	for bound, target := range scope.Imports {
		// Shape 1: `from <mod> import X [as bound]` → target "<mod>.X".
		if dot := strings.LastIndex(target, "."); dot > 0 {
			mod := target[:dot]
			name := target[dot+1:]
			if byName, ok := producers[mod]; ok {
				if prod, ok := byName[name]; ok {
					// Read token is the bound name in the reader's namespace.
					out[bound] = prod
					continue
				}
			}
		}
		// Shape 2: `import <mod> [as bound]` → target "<mod>"; qualified
		// access `bound.<global>` reads any producer global of that module.
		if byName, ok := producers[target]; ok {
			for name, prod := range byName {
				out[bound+"."+name] = prod
			}
		}
	}
	return out
}

// scanGlobalReaderForSinks scans one reader body for a sink reading an imported
// module global. It reuses scanReaderForStoredSinksBare with isGlobal=true so
// the read token is matched as a bare/qualified identifier and the finding
// renders module-global labels. The producer node is synthetic (function-less
// module), so a lightweight FuncNode stand-in carries the producer file/line
// for the taint-path source step.
func scanGlobalReaderForSinks(
	cfg storedStateLangConfig,
	prod pyGlobalProducer,
	reader *FuncNode,
	lines []string,
	offsets []int,
	fields map[string]storedFieldProducer,
	sinkPatterns []storedStateSinkPattern,
	seen map[string]bool,
) []rules.Finding {
	// Give the synthetic producer record a FuncNode so buildStoredStateFinding
	// can render the source step. The "function" is the producer module itself.
	synth := &FuncNode{
		Name:     prod.module,
		FilePath: prod.file,
	}
	for k := range fields {
		f := fields[k]
		f.node = synth
		fields[k] = f
	}
	return scanReaderForStoredSinksBare(
		cfg, prod.module, true /*isGlobal*/, false, reader, lines, offsets, fields, sinkPatterns, seen,
	)
}
