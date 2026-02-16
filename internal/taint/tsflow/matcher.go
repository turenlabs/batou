package tsflow

import (
	"strings"

	"github.com/turenlabs/batou/internal/ast"
	"github.com/turenlabs/batou/internal/taint"
)

// tsMatcher indexes catalog entries by method name for O(1) lookup
// and matches tree-sitter nodes against source/sink/sanitizer definitions.
type tsMatcher struct {
	sourcesByMethod    map[string][]*taint.SourceDef
	sinksByMethod      map[string][]*taint.SinkDef
	sanitizersByMethod map[string][]*taint.SanitizerDef
	cfg                *langConfig
}

func newTSMatcher(sources []taint.SourceDef, sinks []taint.SinkDef, sanitizers []taint.SanitizerDef, cfg *langConfig) *tsMatcher {
	m := &tsMatcher{
		sourcesByMethod:    make(map[string][]*taint.SourceDef),
		sinksByMethod:      make(map[string][]*taint.SinkDef),
		sanitizersByMethod: make(map[string][]*taint.SanitizerDef),
		cfg:                cfg,
	}

	for i := range sources {
		src := &sources[i]
		for _, name := range extractMethodNames(src.MethodName) {
			m.sourcesByMethod[name] = append(m.sourcesByMethod[name], src)
		}
	}
	for i := range sinks {
		sink := &sinks[i]
		for _, name := range extractMethodNames(sink.MethodName) {
			m.sinksByMethod[name] = append(m.sinksByMethod[name], sink)
		}
	}
	for i := range sanitizers {
		san := &sanitizers[i]
		for _, name := range extractMethodNames(san.MethodName) {
			m.sanitizersByMethod[name] = append(m.sanitizersByMethod[name], san)
		}
	}

	return m
}

// extractMethodNames splits compound method names on "/" and extracts the
// final component after any "." or "::" for each part.
func extractMethodNames(methodName string) []string {
	// Normalize "::" to "." for languages like Rust/C++ that use :: scope resolution.
	methodName = strings.ReplaceAll(methodName, "::", ".")
	parts := strings.Split(methodName, "/")
	var names []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		dotParts := strings.Split(p, ".")
		name := dotParts[len(dotParts)-1]
		if name != "" && name != "*" {
			names = append(names, name)
		}
	}
	return names
}

// matchSourceCall checks if a call node matches a known taint source.
func (m *tsMatcher) matchSourceCall(n *ast.Node) *taint.SourceDef {
	methodName := m.cfg.extractCallName(n)
	if methodName == "" {
		return nil
	}

	candidates := m.sourcesByMethod[methodName]
	receiver := m.cfg.extractCallReceiver(n)
	for _, src := range candidates {
		if matchesCatalogEntry(receiver, methodName, src.ObjectType, src.MethodName) {
			return src
		}
	}
	return nil
}

// matchSourceAttr checks if an attribute access node matches a known source.
// This handles sources like request.args, request.body that are property accesses.
func (m *tsMatcher) matchSourceAttr(n *ast.Node) *taint.SourceDef {
	attrName := m.cfg.extractAttrName(n)
	if attrName == "" {
		return nil
	}

	candidates := m.sourcesByMethod[attrName]
	receiver := m.cfg.extractAttrReceiver(n)
	for _, src := range candidates {
		if matchesCatalogEntry(receiver, attrName, src.ObjectType, src.MethodName) {
			return src
		}
	}
	return nil
}

// matchSinkCall checks if a call node matches a known sink.
// Returns the sink and the dangerous argument nodes.
func (m *tsMatcher) matchSinkCall(n *ast.Node) (*taint.SinkDef, []*ast.Node) {
	methodName := m.cfg.extractCallName(n)
	if methodName == "" {
		return nil, nil
	}

	candidates := m.sinksByMethod[methodName]
	receiver := m.cfg.extractCallReceiver(n)
	for _, sink := range candidates {
		if matchesCatalogEntry(receiver, methodName, sink.ObjectType, sink.MethodName) {
			args := m.cfg.extractCallArgs(n)
			dangerous := collectDangerousArgs(args, sink.DangerousArgs)
			return sink, dangerous
		}
	}
	return nil, nil
}

// matchSanitizer checks if a call node matches a known sanitizer.
// Returns the sanitizer and the first argument node.
func (m *tsMatcher) matchSanitizer(n *ast.Node) (*taint.SanitizerDef, *ast.Node) {
	methodName := m.cfg.extractCallName(n)
	if methodName == "" {
		return nil, nil
	}

	candidates := m.sanitizersByMethod[methodName]
	receiver := m.cfg.extractCallReceiver(n)
	for _, san := range candidates {
		if matchesCatalogEntry(receiver, methodName, san.ObjectType, san.MethodName) {
			args := m.cfg.extractCallArgs(n)
			if len(args) > 0 {
				return san, args[0]
			}
			return san, nil
		}
	}
	return nil, nil
}

// matchesCatalogEntry checks if a receiver+method pair plausibly matches
// a catalog entry's objectType+methodName.
func matchesCatalogEntry(receiver, callMethod, catObjectType, catMethodName string) bool {
	// Normalize "::" to "." for languages like Rust/C++ that use :: scope resolution.
	catMethodName = strings.ReplaceAll(catMethodName, "::", ".")

	// Check method name matches one of the compound parts
	matched := false
	for _, candidate := range strings.Split(catMethodName, "/") {
		candidate = strings.TrimSpace(candidate)
		dotParts := strings.Split(candidate, ".")
		finalMethod := dotParts[len(dotParts)-1]
		if callMethod == finalMethod || finalMethod == "*" {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}

	// No object type required — always match
	if catObjectType == "" {
		return true
	}

	// Check receiver heuristic
	if receiver == "" {
		return false
	}

	lower := strings.ToLower(receiver)
	catLower := strings.ToLower(catObjectType)

	// Direct name match
	if lower == catLower {
		return true
	}

	// Common receiver name patterns
	if strings.Contains(catLower, "request") {
		if lower == "request" || lower == "req" || lower == "r" || lower == "self.request" {
			return true
		}
	}
	if strings.Contains(catLower, "response") {
		if lower == "response" || lower == "res" || lower == "resp" {
			return true
		}
	}
	if strings.Contains(catLower, "cursor") {
		if lower == "cursor" || lower == "cur" || lower == "c" || lower == "db" {
			return true
		}
	}
	if strings.Contains(catLower, "connection") || strings.Contains(catLower, "conn") {
		if lower == "conn" || lower == "connection" || lower == "db" {
			return true
		}
	}
	if strings.Contains(catLower, "statement") {
		if lower == "stmt" || lower == "statement" || lower == "ps" || lower == "pstmt" {
			return true
		}
	}
	if strings.Contains(catLower, "runtime") {
		if lower == "runtime" || strings.Contains(lower, "runtime") {
			return true
		}
	}
	if strings.Contains(catLower, "session") {
		if lower == "session" || lower == "sess" || lower == "s" {
			return true
		}
	}
	if strings.Contains(catLower, "database") {
		if lower == "db" || lower == "database" || lower == "sqlite" || lower == "sqlitedb" {
			return true
		}
	}

	// Partial match: "Request" matches "flask.Request", "express.Request", etc.
	normalized := strings.ReplaceAll(catObjectType, "::", ".")
	typeParts := strings.Split(normalized, ".")
	lastPart := strings.ToLower(typeParts[len(typeParts)-1])
	if lower == lastPart {
		return true
	}

	// Abbreviation heuristic: receiver is a prefix of the type name
	// (e.g., "stmt" is a prefix of "statement", "req" is a prefix of "request")
	if len(lower) >= 2 && strings.HasPrefix(lastPart, lower) {
		return true
	}

	// Rust/C++ struct-method heuristic: receiver matches a component of the
	// method name (e.g., receiver "Command" matches catMethodName "Command::new").
	normalizedMethod := strings.ReplaceAll(catMethodName, "::", ".")
	for _, part := range strings.Split(normalizedMethod, ".") {
		if strings.EqualFold(lower, part) {
			return true
		}
	}

	return false
}

// collectDangerousArgs returns argument nodes at the dangerous positions.
func collectDangerousArgs(args []*ast.Node, dangerousArgs []int) []*ast.Node {
	var dangerous []*ast.Node
	for _, argIdx := range dangerousArgs {
		if argIdx == -1 {
			dangerous = append(dangerous, args...)
			break
		}
		if argIdx >= 0 && argIdx < len(args) {
			dangerous = append(dangerous, args[argIdx])
		}
	}
	return dangerous
}
