// Cross-language HTTP service-boundary taint.
//
// A database-per-language SAST engine builds one database per language and
// cannot follow a request that leaves a JavaScript front-end and lands in a
// Python (or Express) back-end handler. Most engines treat route registrations as configuration,
// not dataflow. Batou keeps ONE call graph over all supported languages,
// so it can link the two sides of a service boundary by the one thing
// they share at the source level: the literal request PATH.
//
// The shape this file handles:
//
//	frontend.js   fetch("/api/items?q=" + req.query.q)   ← OUTBOUND site
//	backend.py    @app.route("/api/items")                ← ROUTE handler
//	              def items(): cursor.execute(... request.args["q"] ...)  ← SINK
//
// Route-handler nodes already exist in the graph (the JS/Python builders
// emit a FuncNode for the handler callback / decorated def). The two
// missing pieces, both added here:
//
//  1. Path literals are captured on the nodes at build time:
//     FuncNode.RoutePath on handler nodes, FuncNode.OutboundRequests on
//     the function that issues the request.
//  2. linkServiceBoundaryEdges (called from ResolveCrossFileEdges) matches
//     an OutboundRequest's path to a route handler's RoutePath, in a
//     DIFFERENT file, regardless of language. On a match it (a) adds a
//     cross-file Calls/CalledBy edge so downstream consumers see the
//     dependency, and (b) synthesises a cross-language taint finding when
//     the handler forwards request input into a sink.
//
// The matcher itself is language-agnostic: it never inspects node
// language. Only the path-capture (per-language, in the builders) and the
// handler's sink population (the existing ensure*CalleeSinks helpers) are
// language-specific.

package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// NormalizeRoutePath canonicalises a raw path literal so an outbound
// request path and a route-registration path compare equal even when one
// carries a query string, a trailing slash, or surrounding quotes.
//
//	"/api/items?q=" + x  → strip the dynamic tail at the first '?' → "/api/items"
//	"/api/items/"        → "/api/items"
//	"api/items"          → "/api/items" (leading slash added)
//	`"/api/items"`       → "/api/items" (quotes trimmed)
//
// An empty or root-only path normalises to "" so it is never matched
// (matching every handler against a bare "/" would be pure noise).
func NormalizeRoutePath(raw string) string {
	p := strings.TrimSpace(raw)
	p = strings.Trim(p, "\"'`")
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	// Drop a query string / fragment if present.
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	// A backtick-template tail like `/api/items/${id}` keeps everything up
	// to the first interpolation so the static prefix still matches a
	// statically-registered route prefix. We deliberately do NOT match
	// parameterised routes here (that is design-noted future work); the
	// static-prefix trim just avoids a spurious "${...}" suffix.
	if i := strings.Index(p, "${"); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// Strip a single trailing slash (but keep the root "/").
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	if p == "" || p == "/" {
		return ""
	}
	return p
}

// methodsCompatible reports whether an outbound request method and a
// route-handler method can refer to the same endpoint. An empty value on
// either side means "unknown / any" and is treated as compatible — we
// would rather link than miss a flow on a method we failed to capture.
func methodsCompatible(outbound, handler string) bool {
	outbound = strings.ToLower(strings.TrimSpace(outbound))
	handler = strings.ToLower(strings.TrimSpace(handler))
	if outbound == "" || handler == "" {
		return true
	}
	return outbound == handler
}

// linkServiceBoundaryEdges is the path-literal matcher invoked at the end
// of ResolveCrossFileEdges. It walks every node carrying OutboundRequests
// and links each tainted request to the in-repo route handler that serves
// the matching path, in a different file. Returns the synthesised
// cross-language taint findings (deterministically ordered) so the caller
// can emit them alongside the same-language cross-file findings.
//
// The returned findings are NOT persisted on the graph; they are produced
// fresh on each scan from the (persisted) RoutePath / OutboundRequests
// node metadata.
func linkServiceBoundaryEdges(cg *CallGraph) []rules.Finding {
	if cg == nil || len(cg.Nodes) == 0 {
		return nil
	}

	// Index route-handler nodes by normalised path. A path may have more
	// than one handler node (e.g. duplicate registrations); keep them all.
	handlersByPath := make(map[string][]*FuncNode)
	for _, n := range cg.Nodes {
		if n == nil || n.RoutePath == "" {
			continue
		}
		handlersByPath[n.RoutePath] = append(handlersByPath[n.RoutePath], n)
	}
	if len(handlersByPath) == 0 {
		return nil
	}

	// Sort outbound caller IDs so the emitted findings are reproducible
	// across runs (map iteration is randomised).
	callerIDs := make([]string, 0, len(cg.Nodes))
	for id, n := range cg.Nodes {
		if n != nil && len(n.OutboundRequests) > 0 {
			callerIDs = append(callerIDs, id)
		}
	}
	sort.Strings(callerIDs)

	var findings []rules.Finding
	// Dedup: one finding per (outbound site line, handler sink). The same
	// outbound path matched against multiple identical handler
	// registrations should not multiply.
	seen := make(map[string]bool)

	for _, callerID := range callerIDs {
		caller := cg.Nodes[callerID]
		for _, ob := range caller.OutboundRequests {
			if ob.TaintedArg == "" || ob.Path == "" {
				continue
			}
			handlers := handlersByPath[ob.Path]
			if len(handlers) == 0 {
				continue
			}
			// Deterministic handler order.
			sortedHandlers := append([]*FuncNode(nil), handlers...)
			sort.Slice(sortedHandlers, func(i, j int) bool {
				return sortedHandlers[i].ID < sortedHandlers[j].ID
			})
			for _, handler := range sortedHandlers {
				if handler.FilePath == caller.FilePath {
					// Same-file is the in-language case other layers cover.
					continue
				}
				if !methodsCompatible(ob.Method, handler.RouteMethod) {
					continue
				}
				// Add the cross-file dependency edge regardless of whether
				// a finding is produced — the request DOES reach the
				// handler. (AddEdge is idempotent on both directions.)
				cg.AddEdge(caller.ID, handler.ID)

				// Populate the handler's sinks lazily (the per-file walker
				// doesn't regex-scan JS/Python sinks). Both helpers are
				// idempotent no-ops for the wrong language.
				ensureJavaScriptCalleeSinks(cg, handler)
				if handler.Language == rules.LangPython {
					ensurePythonCalleeSinks(cg, handler)
				}

				sink := firstHandlerSink(handler)
				if sink == nil {
					continue
				}
				key := fmt.Sprintf("%s:%d|%s:%d", caller.FilePath, ob.Line, handler.FilePath, sink.Line)
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, buildCrossLangFinding(caller, ob, handler, sink))
			}
		}
	}
	return findings
}

// firstHandlerSink returns the first non-suppressed SinkCall on a route
// handler node, or nil when the handler forwards nothing dangerous.
// Sinks are returned in line order for deterministic finding output.
func firstHandlerSink(handler *FuncNode) *SinkRef {
	if handler == nil || len(handler.TaintSig.SinkCalls) == 0 {
		return nil
	}
	sinks := append([]SinkRef(nil), handler.TaintSig.SinkCalls...)
	sort.Slice(sinks, func(i, j int) bool { return sinks[i].Line < sinks[j].Line })
	return &sinks[0]
}

// buildCrossLangFinding synthesises the cross-language taint finding for a
// matched (outbound request → route handler → sink) chain. The TaintPath
// spans both files and both languages: the source is the outbound request
// site in the caller's file/language, the sink is the dangerous call in
// the handler's file/language.
func buildCrossLangFinding(caller *FuncNode, ob OutboundRequest, handler *FuncNode, sink *SinkRef) rules.Finding {
	sev := severityForSinkCategory[sink.SinkCategory]
	if sev < rules.High {
		sev = rules.High
	}
	cwe := cweForSinkCategory[sink.SinkCategory]
	owasp := owaspForSinkCategory[sink.SinkCategory]

	sinkLabel := sink.MethodName
	if sinkLabel == "" {
		sinkLabel = string(sink.SinkCategory)
	}
	srcCat := ob.SourceCategory
	if srcCat == "" {
		srcCat = string(taint.SrcUserInput)
	}

	sinkFile, sinkLine := handlerSinkLocation(handler, sink)

	taintPath := []rules.TaintStep{
		{
			File:  caller.FilePath,
			Line:  ob.Line,
			Kind:  rules.TaintStepSource,
			Label: fmt.Sprintf("tainted outbound request to %q carries %s", ob.Path, ob.TaintedArg),
		},
		{
			File:  caller.FilePath,
			Line:  ob.Line,
			Kind:  rules.TaintStepPropagation,
			Label: fmt.Sprintf("HTTP %s %s crosses the service boundary", upperOrAny(ob.Method), ob.Path),
		},
		{
			File:  handler.FilePath,
			Line:  handler.StartLine,
			Kind:  rules.TaintStepPropagation,
			Label: fmt.Sprintf("received by in-repo route handler %s (%s) for %s", handler.Name, handler.Language, ob.Path),
		},
		{
			File:  sinkFile,
			Line:  sinkLine,
			Kind:  rules.TaintStepSink,
			Label: fmt.Sprintf("%s (in %s)", sinkLabel, handler.Name),
		},
	}

	return rules.Finding{
		RuleID:        fmt.Sprintf("BATOU-CROSSLANG-%s", strings.ToUpper(string(sink.SinkCategory))),
		Severity:      sev,
		SeverityLabel: sev.String(),
		Title: fmt.Sprintf(
			"Cross-language taint: %s outbound request to %q flows into %s handler sink %s",
			caller.Language, ob.Path, handler.Language, sinkLabel,
		),
		Description: fmt.Sprintf(
			"An outbound HTTP request in %s (%s:%d) sends user-controlled data (%s) to the in-repo route %q. "+
				"That route is served by the %s handler %s (%s:%d), which forwards request input into %s without sanitization. "+
				"Taint crosses the %s→%s service boundary, producing a cross-language %s vulnerability that "+
				"per-language analyzers (one DB per language) cannot see.",
			caller.Language, caller.FilePath, ob.Line, ob.TaintedArg, ob.Path,
			handler.Language, handler.Name, handler.FilePath, handler.StartLine,
			sinkLabel, caller.Language, handler.Language, sink.SinkCategory,
		),
		FilePath:   caller.FilePath,
		LineNumber: ob.Line,
		MatchedText: fmt.Sprintf(
			"%s -> %q -> %s() -> %s %s",
			ob.TaintedArg, ob.Path, handler.Name, sinkLabel, formatSinkLocation(*sink, handler.FilePath),
		),
		TaintPath: taintPath,
		Suggestion: fmt.Sprintf(
			"Validate and sanitize the request input consumed by %s before passing it to %s, "+
				"and constrain the outbound request in %s to known-safe values.",
			handler.Name, sinkLabel, caller.FilePath,
		),
		CWEID:           cwe,
		OWASPCategory:   owasp,
		Confidence:      "high",
		ConfidenceScore: 0.8,
		SourceCategory:  srcCat,
		SinkCategory:    string(sink.SinkCategory),
		Language:        handler.Language,
		Tags: []string{
			"interprocedural", "taint-analysis", "cross-language", "service-boundary",
			string(caller.Language) + "->" + string(handler.Language),
			string(sink.SinkCategory),
		},
	}
}

// handlerSinkLocation resolves the physical (file, line) of a handler's
// sink. For sinks lifted up the call graph by signature propagation the
// leaf location lives in OriginFile/OriginLine; otherwise the sink is a
// first-class call in the handler's own file at SinkRef.Line.
func handlerSinkLocation(handler *FuncNode, sink *SinkRef) (string, int) {
	if sink.OriginFile != "" {
		return sink.OriginFile, sink.OriginLine
	}
	return handler.FilePath, sink.Line
}

// upperOrAny renders an HTTP method for display, falling back to "ANY"
// when the method wasn't captured.
func upperOrAny(m string) string {
	m = strings.ToUpper(strings.TrimSpace(m))
	if m == "" {
		return "ANY"
	}
	return m
}
