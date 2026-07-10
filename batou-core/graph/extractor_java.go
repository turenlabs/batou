package graph

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// javaExtractor extracts typed function summaries from Java source by
// walking the tree-sitter Java grammar. It's the first non-Go reference
// implementation of TypeExtractor; per-language PRs for other
// static-typed languages (TypeScript, Kotlin, C#, Swift, Rust, C++)
// should mirror this structure.
//
// Scope of this initial implementation:
//   - Top-level classes and their methods/constructors. Nested classes
//     and method receivers inside are walked with "Outer.Inner.method"
//     naming so FuncNode IDs line up with what the Java builder emits.
//   - Canonical types use FQN when an import resolves the short name,
//     else the raw short name. Star imports (`import javax.servlet.*`)
//     are not resolved — a known MVP gap; can be added later.
//   - Source/sink type matching is via javaTypeCatalog (see below).
//     Additional framework types are expected to arrive via loop PRs.
type javaExtractor struct{}

func (javaExtractor) Language() rules.Language { return rules.LangJava }

func (javaExtractor) ExtractFunctions(ctx *ExtractContext) []FuncSignature {
	tree := javaTree(ctx)
	if tree == nil {
		return nil
	}
	imports := extractJavaImports(tree.Root())
	var sigs []FuncSignature
	walkJavaTypes(tree.Root(), "", imports, &sigs)
	return sigs
}

// ResolveVarType is intentionally unimplemented for Java in this PR —
// per-language call-site arg-type resolution (the confidence-bump path)
// is a follow-up (see todo.json E1-T2 notes). Returning "" gracefully
// degrades to no bump, same as a dynamic language.
func (javaExtractor) ResolveVarType(ctx *ExtractContext, varName string, line int) string {
	return ""
}

func javaTree(ctx *ExtractContext) *ast.Tree {
	if ctx == nil {
		return nil
	}
	if t, ok := ctx.TSTree.(*ast.Tree); ok && t != nil {
		return t
	}
	if ctx.Content == nil {
		return nil
	}
	return ast.Parse(ctx.Content, rules.LangJava)
}

// extractJavaImports walks import_declaration nodes and returns a map
// from short type name (e.g. "HttpServletRequest") to fully-qualified
// name (e.g. "javax.servlet.http.HttpServletRequest"). Star imports
// and static imports are ignored.
func extractJavaImports(root *ast.Node) map[string]string {
	imports := map[string]string{}
	if root == nil {
		return imports
	}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() != "import_declaration" {
			return true
		}
		// Skip static imports — they import members, not types.
		text := n.Text()
		if strings.HasPrefix(text, "import static") {
			return false
		}
		// Find the scoped_identifier child; its text is the FQN.
		for _, c := range n.NamedChildren() {
			if c.Type() == "scoped_identifier" || c.Type() == "identifier" {
				fqn := strings.TrimSuffix(strings.TrimSpace(c.Text()), ";")
				if strings.HasSuffix(fqn, ".*") {
					// Star import — skip; MVP limitation.
					return false
				}
				short := fqn
				if dot := strings.LastIndexByte(fqn, '.'); dot >= 0 {
					short = fqn[dot+1:]
				}
				imports[short] = fqn
				return false
			}
		}
		return false
	})
	return imports
}

// walkJavaTypes recurses into class/interface/record declarations,
// threading the enclosing type path as a dot-separated prefix
// ("" at top level → "Handler" → "Handler.Inner"). Method names are
// emitted as "<prefix>.<methodName>" to match the canonical FuncNode
// name the graph builder uses.
func walkJavaTypes(n *ast.Node, prefix string, imports map[string]string, sigs *[]FuncSignature) {
	if n == nil {
		return
	}
	for _, child := range n.NamedChildren() {
		switch child.Type() {
		case "class_declaration", "interface_declaration", "record_declaration", "enum_declaration":
			name := nodeFieldText(child, "name")
			childPrefix := name
			if prefix != "" && name != "" {
				childPrefix = prefix + "." + name
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkJavaTypes(body, childPrefix, imports, sigs)
			}
		case "method_declaration":
			sig := extractJavaMethod(child, prefix, imports, false)
			if sig != nil {
				*sigs = append(*sigs, *sig)
			}
		case "constructor_declaration":
			sig := extractJavaMethod(child, prefix, imports, true)
			if sig != nil {
				*sigs = append(*sigs, *sig)
			}
		default:
			walkJavaTypes(child, prefix, imports, sigs)
		}
	}
}

func extractJavaMethod(n *ast.Node, prefix string, imports map[string]string, isCtor bool) *FuncSignature {
	name := nodeFieldText(n, "name")
	if name == "" {
		return nil
	}
	fullName := name
	if prefix != "" {
		fullName = prefix + "." + name
	}
	sig := &FuncSignature{
		Name:      fullName,
		StartLine: int(n.StartRow()) + 1,
		EndLine:   int(n.EndRow()) + 1,
	}
	if params := n.ChildByFieldName("parameters"); params != nil {
		sig.Params = extractJavaParams(params, imports, n)
	}
	if !isCtor {
		if ret := n.ChildByFieldName("type"); ret != nil {
			rawType := strings.TrimSpace(ret.Text())
			canonical := canonicalizeJavaType(rawType, imports)
			r := ReturnTaint{
				Index:         0,
				Type:          rawType,
				CanonicalType: canonical,
			}
			if cat, ok := javaTypeCatalog.LookupSourceReturn(canonical); ok {
				r.IsSourceType = true
				r.SourceCategory = cat
			} else if cat, ok := javaTypeCatalog.LookupSource(canonical); ok {
				r.IsSourceType = true
				r.SourceCategory = cat
			}
			sig.Returns = append(sig.Returns, r)
		}
	}
	return sig
}

// extractJavaParams extracts ParamTaint records from a `parameters`
// node. DI types in javaDIParamTypeAllowlist (RedirectAttributes,
// Model, Authentication, BindingResult, …) are skipped from the
// type-catalog auto-tag because they are server-managed parameters,
// not user-input. Per-param framework annotations (@RequestParam,
// @PathVariable, …) still tag any non-numeric parameter type.
//
// `methodNode` is the enclosing method (or constructor) declaration;
// it's used by the handler-gate pass below to decide whether the
// method is a web/messaging handler whose parameters can be treated as
// user-input even when their type is otherwise unremarkable
// (String / DTO). When `methodNode` is nil (e.g. tests that call
// extractJavaParams directly), the handler-gate is a no-op and only
// the existing type-catalog and per-param annotation paths fire.
func extractJavaParams(params *ast.Node, imports map[string]string, methodNode *ast.Node) []ParamTaint {
	// Resolved once per method so that the per-param loop below can
	// cheaply consult it. The walk itself is O(annotations on the
	// method + ancestor class), which is tiny in practice.
	methodIsHandler := javaMethodIsHandler(methodNode)
	var out []ParamTaint
	idx := 0
	for _, child := range params.NamedChildren() {
		if child.Type() != "formal_parameter" && child.Type() != "spread_parameter" {
			continue
		}
		var rawType, name string
		if child.Type() == "formal_parameter" {
			if typeNode := child.ChildByFieldName("type"); typeNode != nil {
				rawType = strings.TrimSpace(typeNode.Text())
			}
			if nameNode := child.ChildByFieldName("name"); nameNode != nil {
				name = strings.TrimSpace(nameNode.Text())
			}
		} else {
			// spread_parameter (Java varargs: `String... args`).
			// tree-sitter layout: [modifiers]? type variable_declarator.
			// Extract type from first non-declarator named child, name
			// from the variable_declarator's identifier.
			for _, c := range child.NamedChildren() {
				switch c.Type() {
				case "variable_declarator":
					if id := c.ChildByFieldName("name"); id != nil {
						name = strings.TrimSpace(id.Text())
					} else {
						// Fallback: first identifier child.
						for _, gc := range c.NamedChildren() {
							if gc.Type() == "identifier" {
								name = strings.TrimSpace(gc.Text())
								break
							}
						}
					}
				case "modifiers":
					// Skip.
				default:
					if rawType == "" {
						rawType = strings.TrimSpace(c.Text())
					}
				}
			}
			rawType = rawType + "..."
		}
		canonical := canonicalizeJavaType(rawType, imports)
		p := ParamTaint{
			Index:         idx,
			Name:          name,
			Type:          rawType,
			CanonicalType: canonical,
		}
		// PR-CATjava (Fix 2): Spring DI injects RedirectAttributes /
		// Model / Authentication / Principal / BindingResult /
		// SessionStatus / HttpSession as parameters that are NOT
		// user input. Skip the type-catalog auto-tag for them, even
		// on handler methods. The triage data showed every
		// petclinic FP was a RedirectAttributes auto-tag.
		if !javaDIParamTypeAllowlist[canonical] {
			if cat, ok := javaTypeCatalog.LookupSource(canonical); ok {
				p.IsSourceType = true
				p.SourceCategory = cat
			}
		}
		// PR-BBjava: when the formal_parameter carries a known framework
		// annotation (@RequestParam, @PathParam, @QueryValue, …), tag
		// the parameter as a source. This complements the type-based
		// lookup above — the annotation often binds to a primitive /
		// String parameter whose type alone wouldn't trigger anything.
		// The annotation-derived tag wins over the type lookup so the
		// IsSourceType flag survives even when the parameter type isn't
		// in the type catalog.
		//
		// PR-CATjava (Fix 3): when the annotated param is numerically /
		// UUID typed, skip the tag — Jackson rejects malformed input
		// before the controller body runs.
		if !p.IsSourceType {
			if cat, ok := javaFrameworkAnnotationSource(child); ok {
				if !javaNumericTypeAllowlist[canonical] {
					p.IsSourceType = true
					p.SourceCategory = cat
				}
			}
		}
		// PR-CATjava-1-deferred (Fix 1): handler-method auto-tag.
		// When the enclosing method carries a recognised handler
		// annotation (@GetMapping, @Path + @GET, @KafkaListener, …)
		// the controller / listener boundary itself is the source of
		// untrusted data, so every otherwise-unmarked parameter is
		// treated as user input. This complements the type-catalog
		// (HttpServletRequest …) and per-param annotation
		// (@RequestParam …) paths above:
		//
		//   - DI types (RedirectAttributes, Model, Authentication, …)
		//     are still suppressed — they're server-managed handles,
		//     not user input.
		//   - Numeric / UUID types are still suppressed — Jackson
		//     rejects malformed inputs before the handler body runs.
		//
		// The handler gate uses AST annotation matching only — no
		// substring scan of the body — so sentry-java helpers like
		// `processFile(File file, Hint hint)` whose body happens to
		// mention `Path(` via `getAbsolutePath()` are NOT treated as
		// handlers and their parameters stay untagged.
		if !p.IsSourceType && methodIsHandler {
			if !javaDIParamTypeAllowlist[canonical] && !javaNumericTypeAllowlist[canonical] {
				p.IsSourceType = true
				p.SourceCategory = taint.SrcUserInput
			}
		}
		if cat, ok := javaTypeCatalog.LookupSink(canonical); ok {
			p.IsSinkType = true
			p.SinkCategory = cat
		}
		out = append(out, p)
		idx++
	}
	return out
}

// canonicalizeJavaType resolves a raw Java type expression to its FQN
// using the import map. Handles:
//   - Plain type: "HttpServletRequest" → "javax.servlet.http.HttpServletRequest"
//   - Already-FQN: "javax.servlet.http.HttpServletRequest" → unchanged
//   - Generic: "List<String>" → "java.util.List<String>" (head resolved,
//     body left as-is for MVP)
//   - Array: "String[]" → "String[]" (short kept; array semantics preserved)
//   - Unresolved: returns the input unchanged
func canonicalizeJavaType(raw string, imports map[string]string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Split off generics and arrays so we can resolve just the head.
	head := raw
	tail := ""
	if i := strings.IndexAny(raw, "<["); i >= 0 {
		head = raw[:i]
		tail = raw[i:]
	}
	head = strings.TrimSpace(head)
	if strings.Contains(head, ".") {
		// Already qualified — return as-is (preserving generics/arrays).
		return raw
	}
	if fqn, ok := imports[head]; ok {
		return fqn + tail
	}
	return raw
}

// nodeFieldText returns the trimmed text of a named field child, or ""
// if the child is absent.
func nodeFieldText(n *ast.Node, field string) string {
	if n == nil {
		return ""
	}
	c := n.ChildByFieldName(field)
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.Text())
}

// javaTypeCatalog is the initial Java framework source/sink type
// catalog. Covers the most common servlet + Spring + JDBC patterns that
// appear in OWASP Benchmark test cases. Additional framework coverage
// (Micronaut, Quarkus, Vert.x, Reactor, Play, etc.) belongs in follow-up
// loop PRs.
//
// Keys use fully-qualified Java class names as produced by
// canonicalizeJavaType.
var javaTypeCatalog = &TypeCatalog{
	SourceParam: map[string]taint.SourceCategory{
		// Servlet API (javax namespace — pre-Jakarta)
		"javax.servlet.http.HttpServletRequest": taint.SrcUserInput,
		"javax.servlet.ServletRequest":          taint.SrcUserInput,
		"javax.servlet.http.Cookie":             taint.SrcUserInput,

		// Servlet API (Jakarta namespace — Java EE 9+)
		"jakarta.servlet.http.HttpServletRequest": taint.SrcUserInput,
		"jakarta.servlet.ServletRequest":          taint.SrcUserInput,
		"jakarta.servlet.http.Cookie":             taint.SrcUserInput,

		// JAX-RS
		"javax.ws.rs.container.ContainerRequestContext":   taint.SrcUserInput,
		"jakarta.ws.rs.container.ContainerRequestContext": taint.SrcUserInput,

		// Spring
		"org.springframework.http.HttpRequest":              taint.SrcUserInput,
		"org.springframework.http.server.ServerHttpRequest": taint.SrcUserInput,
		"org.springframework.web.multipart.MultipartFile":   taint.SrcUserInput,

		// Servlet response
		"javax.servlet.http.HttpServletResponse":   taint.SrcExternal,
		"jakarta.servlet.http.HttpServletResponse": taint.SrcExternal,

		// JDBC
		"java.sql.ResultSet": taint.SrcDatabase,

		// I/O
		"java.io.InputStream": taint.SrcNetwork,
		"java.io.Reader":      taint.SrcNetwork,
		"java.net.Socket":     taint.SrcNetwork,
	},
	SinkParam: map[string]taint.SinkCategory{
		"java.sql.PreparedStatement": taint.SnkSQLQuery,
		"java.sql.Statement":         taint.SnkSQLQuery,
	},
	SourceReturn: map[string]taint.SourceCategory{
		"javax.servlet.http.HttpServletRequest":   taint.SrcUserInput,
		"jakarta.servlet.http.HttpServletRequest": taint.SrcUserInput,
	},
}

// JavaTypeCatalog returns the Java type catalog. Exposed for tests and
// for per-language PRs that want to compare catalog shape.
func JavaTypeCatalog() *TypeCatalog { return javaTypeCatalog }

func init() {
	RegisterExtractor(javaExtractor{})
}
