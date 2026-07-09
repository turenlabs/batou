// PR-BBjava: framework-annotation source detection for the Java
// cross-file extractor. Mirrors batou-core/graph/extractor_javascript_typecatalog.go
// (NestJS-style decorators on parameters) and the param-binding
// annotations the catalog already models at the regex tier.
//
// What this adds beyond the typed-parameter shape already supported by
// javaTypeCatalog:
//
//  1. javaFrameworkParamAnnotations — the set of well-known parameter
//     annotations (Spring MVC, JAX-RS, Micronaut, Quarkus RESTEasy
//     Reactive) that mark a handler parameter as carrying untrusted
//     request data. When the formal_parameter's `modifiers` child
//     contains a `marker_annotation`/`annotation` whose identifier
//     matches the set, the parameter is tagged as a SrcUserInput source
//     regardless of its Java type (the type is usually a primitive
//     wrapper, `String`, or a DTO that wouldn't otherwise match the type
//     catalog).
//
//  2. Augments the existing type-catalog so reactive / functional
//     handler types (`ServerRequest`, `WebRequest`, `JoinPoint`) flow
//     through the same SourceParam lookup the typed servlet path uses.
//     These additions sit on the existing javaTypeCatalog map in
//     extractor_java.go via the helper below — we deliberately avoid
//     mutating that var literal in two places.
//
// Out of scope (documented as future work):
//
//   - A real walker for Spring AOP `JoinPoint`. Tagging the parameter
//     type is the cheap-but-correct signal that the method receives
//     attacker-controllable args via reflection; a full @Before/@Around
//     argument-flow analyzer belongs in a follow-up PR.
//   - Resolving `import org.springframework.web.bind.annotation.*` star
//     imports. The annotation identifiers we match are local short
//     names (`RequestParam`, `PathVariable`, …). Real-world handler
//     code uses these short names directly — explicit FQN annotations
//     (`@org.springframework.web.bind.annotation.RequestParam`) are
//     extremely rare and would just produce two annotation nodes in the
//     tree-sitter parse; either of those flows triggers the source tag.
package graph

import (
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
)

// javaDIParamTypeAllowlist lists Spring/JAX-RS framework parameter
// types that are dependency-injected into handler methods but are NOT
// user input. The auto-source tag from javaTypeCatalog (or from any
// future addition) is skipped for these types — though an explicit
// per-param @RequestParam-style annotation can still tag them. Cross-
// referenced with the FP triage data in /tmp/batou-scans/petclinic-…
// where every redirectAttributes finding is an FP because the param is
// a controller-side write target, not user input.
//
// Each entry is matched against the canonical (FQN-resolved) type
// after canonicalizeJavaType, so both the import-resolved form
// ("org.springframework.web.servlet.mvc.support.RedirectAttributes")
// and the short form when the import is missing or starred
// ("RedirectAttributes") need to be listed.
var javaDIParamTypeAllowlist = map[string]bool{
	// Spring MVC: RedirectAttributes / view-model
	"org.springframework.web.servlet.mvc.support.RedirectAttributes": true,
	"RedirectAttributes": true,
	"org.springframework.ui.Model":      true,
	"Model":                             true,
	"org.springframework.ui.ModelMap":   true,
	"ModelMap":                          true,
	"org.springframework.web.servlet.ModelAndView": true,
	"ModelAndView": true,

	// Spring Security: server-issued, validated identity
	"org.springframework.security.core.Authentication": true,
	"Authentication": true,
	"java.security.Principal": true,
	"Principal":               true,

	// Spring MVC: form-validation result
	"org.springframework.validation.BindingResult": true,
	"BindingResult": true,
	"org.springframework.validation.Errors": true,
	"Errors": true,

	// Spring MVC: session lifecycle handle
	"org.springframework.web.bind.support.SessionStatus": true,
	"SessionStatus": true,

	// Server-managed session — value writes are flagged at the
	// .setAttribute() sink, not at the param. Auto-tagging the param
	// produces a spurious trust_boundary finding on every controller
	// that touches the session.
	"javax.servlet.http.HttpSession":   true,
	"jakarta.servlet.http.HttpSession": true,
	"HttpSession":                      true,

	// Spring MVC: locale / time-zone are container-resolved.
	"java.util.Locale":   true,
	"Locale":             true,
	"java.util.TimeZone": true,
	"TimeZone":           true,
	"java.time.ZoneId":   true,
	"ZoneId":             true,

	// Servlet OUTPUT objects — never user input. The response is what the
	// handler writes TO; seeding it auto-tags every response.setContentType /
	// setHeader / getWriter call as a spurious tainted-receiver header/XSS flow.
	// (kept in sync with tsflowJavaDIParamTypeAllowlist in tsflow/walker.go)
	"javax.servlet.http.HttpServletResponse":   true,
	"jakarta.servlet.http.HttpServletResponse": true,
	"HttpServletResponse":                      true,
	"javax.servlet.ServletResponse":            true,
	"jakarta.servlet.ServletResponse":          true,
	"ServletResponse":                          true,
}

// javaNumericTypeAllowlist lists Java numeric / UUID / boolean types
// that cannot meaningfully carry SQL injection, command injection, or
// path traversal payloads. When a handler param is annotated with
// @PathVariable / @RequestParam / @PathParam / @QueryParam (etc.) AND
// its type is in this set, we skip the auto-tag. The Jackson /
// Bean-Validation layer will reject anything that doesn't parse to the
// declared numeric type before the controller body runs, so by the
// time the value reaches the handler it's a well-typed number.
//
// A developer who explicitly casts to String (`String id = pathVar.toString()`)
// re-introduces taint downstream — that's an explicit choice and
// would be picked up by other rules anyway. Out of scope here.
var javaNumericTypeAllowlist = map[string]bool{
	// Boxed numeric types
	"Long":       true,
	"Integer":    true,
	"Short":      true,
	"Byte":       true,
	"Float":      true,
	"Double":     true,
	"BigDecimal": true,
	"BigInteger": true,
	"java.math.BigDecimal": true,
	"java.math.BigInteger": true,

	// Primitive numeric types
	"long":   true,
	"int":    true,
	"short":  true,
	"byte":   true,
	"float":  true,
	"double": true,

	// UUID — cannot carry injection payloads (Jackson / converter
	// rejects malformed input before the controller runs).
	"UUID":          true,
	"java.util.UUID": true,

	// Booleans (already not interesting, but listed for completeness).
	"Boolean": true,
	"boolean": true,
}

// javaFrameworkParamAnnotations maps each recognised parameter
// annotation (by its short identifier — i.e. what follows the `@`) to
// the source category it should tag the parameter with. All current
// entries are SrcUserInput because every annotation here binds
// request-derived data (path, query, header, cookie, form, body, …) to
// a handler argument. If a future entry needs a different category
// (e.g. an injected database session), it can be added with the right
// SrcCategory.
//
// Frameworks covered:
//   - Spring MVC / Spring Boot: @RequestParam, @RequestBody, @RequestHeader,
//     @PathVariable, @CookieValue, @MatrixVariable, @ModelAttribute,
//     @RequestPart, @SessionAttribute, @RequestAttribute
//   - JAX-RS (Jersey, RESTEasy): @PathParam, @QueryParam, @HeaderParam,
//     @CookieParam, @FormParam, @MatrixParam, @BeanParam
//   - Micronaut: @QueryValue, @Header, @Body, @PathVariable (shared),
//     @CookieValue (shared), @Part, @RequestBean
//   - Quarkus RESTEasy Reactive: @RestQuery, @RestPath, @RestHeader,
//     @RestCookie, @RestForm, @RestMatrix
var javaFrameworkParamAnnotations = map[string]taint.SourceCategory{
	// Spring MVC / Spring Boot
	"RequestParam":     taint.SrcUserInput,
	"RequestBody":      taint.SrcUserInput,
	"RequestHeader":    taint.SrcUserInput,
	"PathVariable":     taint.SrcUserInput,
	"CookieValue":      taint.SrcUserInput,
	"MatrixVariable":   taint.SrcUserInput,
	"ModelAttribute":   taint.SrcUserInput,
	"RequestPart":      taint.SrcUserInput,
	"SessionAttribute": taint.SrcUserInput,
	"RequestAttribute": taint.SrcUserInput,

	// JAX-RS (Jersey, RESTEasy)
	"PathParam":   taint.SrcUserInput,
	"QueryParam":  taint.SrcUserInput,
	"HeaderParam": taint.SrcUserInput,
	"CookieParam": taint.SrcUserInput,
	"FormParam":   taint.SrcUserInput,
	"MatrixParam": taint.SrcUserInput,
	"BeanParam":   taint.SrcUserInput,

	// Micronaut. @PathVariable and @CookieValue share short names with
	// Spring — same source category, same handler shape.
	"QueryValue":  taint.SrcUserInput,
	"Header":      taint.SrcUserInput,
	"Body":        taint.SrcUserInput,
	"Part":        taint.SrcUserInput,
	"RequestBean": taint.SrcUserInput,

	// Quarkus RESTEasy Reactive
	"RestQuery":  taint.SrcUserInput,
	"RestPath":   taint.SrcUserInput,
	"RestHeader": taint.SrcUserInput,
	"RestCookie": taint.SrcUserInput,
	"RestForm":   taint.SrcUserInput,
	"RestMatrix": taint.SrcUserInput,
}

// javaHandlerMethodAnnotations names every annotation that, when applied
// to a method (or — for class-level annotations like @Controller — to
// the enclosing class), means the parameters of that method carry
// request- or message-derived data. We deliberately match a closed set
// instead of `isWebHandlerFunc`'s substring scan of the whole method
// body, which has historically tagged sentry-java helpers like
// `processFile(File file, Hint hint)` as handlers because their body
// contained `file.getAbsolutePath()` (substring "Path("). The AST walk
// only inspects the method's own `modifiers` (and, for class-level
// annotations, its enclosing `class_declaration.modifiers`), so an
// arbitrary call inside the body cannot accidentally tag the method.
//
// Frameworks covered:
//   - Spring MVC / Spring Boot: @RequestMapping, @GetMapping, @PostMapping,
//     @PutMapping, @DeleteMapping, @PatchMapping, @HeadMapping,
//     @OptionsMapping
//   - Spring Messaging (STOMP, WebSocket): @MessageMapping,
//     @SubscribeMapping
//   - JAX-RS / Jersey / RESTEasy / Quarkus: @Path (sufficient — JAX-RS
//     methods on a `@Path`-annotated class inherit the binding), plus
//     the verb-named pseudo-annotations (@GET / @POST / @PUT /
//     @DELETE / @HEAD / @OPTIONS / @PATCH)
//   - Micronaut: @Get, @Post, @Put, @Delete, @Patch, @Head, @Options,
//     and the @Controller class-level annotation
//   - Spring's @KafkaListener / @JmsListener / @RabbitListener /
//     @EventListener: async listeners whose param (`ConsumerRecord`,
//     `TextMessage`, …) carries attacker-controlled payload data
//
// Out of scope (filed as follow-up):
//   - Spring WebFlux router-functional `RouterFunction` factories
//     (@Bean-annotated builder methods)
//   - AOP @Before / @Around advice that wraps annotated handlers; the
//     advice itself isn't a handler so its `JoinPoint` param is already
//     tagged by the framework-typed `javaTypeCatalog` lookup.
var javaHandlerMethodAnnotations = map[string]bool{
	// Spring MVC mappings (verb-specific shortcuts + the generic form).
	"RequestMapping":  true,
	"GetMapping":      true,
	"PostMapping":     true,
	"PutMapping":      true,
	"DeleteMapping":   true,
	"PatchMapping":    true,
	"HeadMapping":     true,
	"OptionsMapping":  true,
	"MessageMapping":  true,
	"SubscribeMapping": true,

	// JAX-RS / Jersey / RESTEasy / Quarkus. `@Path` is enough on its
	// own — every JAX-RS method on a `@Path`-annotated class inherits
	// the binding even when the verb annotation is absent.
	"Path":    true,
	"GET":     true,
	"POST":    true,
	"PUT":     true,
	"DELETE":  true,
	"HEAD":    true,
	"OPTIONS": true,
	"PATCH":   true,

	// Micronaut.
	"Get":     true,
	"Post":    true,
	"Put":     true,
	"Delete":  true,
	"Patch":   true,
	"Head":    true,
	"Options": true,

	// Async listener handlers — their first parameter (Kafka record,
	// JMS message, RabbitMQ delivery, Pulsar message, Spring event)
	// carries attacker-controlled payload data the same way an HTTP
	// handler parameter does, so they qualify as handlers for
	// source-tagging.
	"KafkaListener":   true,
	"JmsListener":     true,
	"RabbitListener":  true,
	"PulsarListener":  true,
	"EventListener":   true,
}

// javaHandlerClassAnnotations is the subset of handler-shaped
// annotations that appear on the enclosing class rather than the
// method. A class with one of these annotations turns every method
// inside it into a handler (this is the JAX-RS / Micronaut
// `@Controller` / `@Path` convention). We accept the class-level
// annotation as a sufficient signal so per-method handlers without
// their own verb annotation (e.g. JAX-RS resource methods with only
// @Path on the class) still get tagged.
var javaHandlerClassAnnotations = map[string]bool{
	"Controller":     true,
	"RestController": true,
	"Path":           true,
}

// javaMethodIsHandler returns true when the method node carries one of
// the recognised handler annotations directly, or — for the
// class-level subset — when an ancestor class declaration carries one.
//
// We deliberately do not consult the body of the method or any
// substring of its text: only AST annotation nodes count. This is what
// keeps sentry-java internal helpers (whose body happens to mention
// `Path(` via `getAbsolutePath()`) from being mis-classified as
// handlers.
func javaMethodIsHandler(methodNode *ast.Node) bool {
	if methodNode == nil {
		return false
	}
	if methodHasAnnotation(methodNode, javaHandlerMethodAnnotations) {
		return true
	}
	// Walk ancestors for a class-level handler annotation. The Java
	// tree-sitter grammar wraps method_declaration nodes inside
	// `class_body` → `class_declaration`; record_declaration and
	// interface_declaration share the same shape. Annotations live on
	// the declaration node's `modifiers` child.
	for p := methodNode.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "class_declaration", "interface_declaration", "record_declaration":
			if methodHasAnnotation(p, javaHandlerClassAnnotations) {
				return true
			}
		}
	}
	return false
}

// methodHasAnnotation returns true when the supplied declaration node's
// `modifiers` child contains a marker_annotation or annotation whose
// short identifier appears in `names`.
func methodHasAnnotation(decl *ast.Node, names map[string]bool) bool {
	if decl == nil {
		return false
	}
	for _, c := range decl.NamedChildren() {
		if c.Type() != "modifiers" {
			continue
		}
		for _, mc := range c.NamedChildren() {
			if mc.Type() != "marker_annotation" && mc.Type() != "annotation" {
				continue
			}
			name := javaAnnotationName(mc)
			if name == "" {
				continue
			}
			if names[name] {
				return true
			}
		}
	}
	return false
}

// javaFrameworkAnnotationSource inspects a formal_parameter's leading
// modifiers for a known framework annotation. Returns the source
// category and true when one is found, else "", false.
//
// Tree-sitter Java grammar shape:
//
//	formal_parameter
//	  modifiers
//	    marker_annotation        // for `@RequestParam` (no args)
//	      identifier             // text: "RequestParam"
//	    annotation               // for `@PathVariable("x")` (with args)
//	      identifier             // text: "PathVariable"
//	      annotation_argument_list
//	  type_identifier
//	  identifier                 // param name
//
// Annotations using a fully-qualified name (e.g.
// `@org.springframework.web.bind.annotation.RequestParam`) produce a
// `scoped_identifier` in place of `identifier`; we take the trailing
// segment so FQN annotations are still recognised.
func javaFrameworkAnnotationSource(param *ast.Node) (taint.SourceCategory, bool) {
	if param == nil {
		return "", false
	}
	for _, c := range param.NamedChildren() {
		if c.Type() != "modifiers" {
			continue
		}
		for _, mc := range c.NamedChildren() {
			if mc.Type() != "marker_annotation" && mc.Type() != "annotation" {
				continue
			}
			name := javaAnnotationName(mc)
			if name == "" {
				continue
			}
			if cat, ok := javaFrameworkParamAnnotations[name]; ok {
				return cat, true
			}
		}
	}
	return "", false
}

// javaAnnotationName extracts the short identifier from a
// marker_annotation / annotation node. The first named child is either
// an `identifier` ("RequestParam") or a `scoped_identifier`
// ("org.springframework.web.bind.annotation.RequestParam"); in the
// scoped case we keep only the trailing segment.
func javaAnnotationName(ann *ast.Node) string {
	for _, c := range ann.NamedChildren() {
		switch c.Type() {
		case "identifier":
			return trimText(c)
		case "scoped_identifier":
			// The deepest right-hand identifier child is the short name.
			// We can rely on Text() and split because Java identifiers
			// can't contain dots themselves.
			text := trimText(c)
			for i := len(text) - 1; i >= 0; i-- {
				if text[i] == '.' {
					return text[i+1:]
				}
			}
			return text
		}
	}
	return ""
}

// trimText is a small helper to keep the annotation-walk readable.
func trimText(n *ast.Node) string {
	if n == nil {
		return ""
	}
	return trimSpaceASCII(n.Text())
}

// trimSpaceASCII trims leading/trailing ASCII whitespace without
// pulling strings.TrimSpace's full unicode table. Java identifiers
// never contain non-ASCII whitespace in the annotation slot, and the
// ast.Node.Text() already returns the source byte slice verbatim.
func trimSpaceASCII(s string) string {
	start, end := 0, len(s)
	for start < end {
		c := s[start]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			break
		}
		start++
	}
	for end > start {
		c := s[end-1]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			break
		}
		end--
	}
	return s[start:end]
}

// javaTypeCatalogFrameworkExtras lists additional framework Request /
// Context types not already in javaTypeCatalog.SourceParam. These are
// registered onto the existing catalog from init() in this file so the
// two extractor source files don't both mutate the same map literal.
var javaTypeCatalogFrameworkExtras = map[string]taint.SourceCategory{
	// Spring WebFlux functional endpoints — ServerRequest is the
	// reactive analogue of HttpServletRequest used by RouterFunction
	// and HandlerFunction handlers.
	"org.springframework.web.reactive.function.server.ServerRequest": taint.SrcUserInput,

	// Spring MVC WebRequest abstraction — the generic Request used by
	// HandlerInterceptor and ControllerAdvice ExceptionHandlers.
	"org.springframework.web.context.request.WebRequest":        taint.SrcUserInput,
	"org.springframework.web.context.request.NativeWebRequest":  taint.SrcUserInput,
	"org.springframework.web.context.request.ServletWebRequest": taint.SrcUserInput,

	// Spring AOP JoinPoint — @Around / @Before advice receives a
	// JoinPoint whose getArgs() yields the (potentially attacker
	// controlled) target-method arguments. We mark the parameter as a
	// user-input source so flows from JoinPoint.getArgs() into a sink
	// propagate. A real AOP walker would attribute taint per pointcut
	// expression; that's a follow-up.
	"org.aspectj.lang.JoinPoint":          taint.SrcUserInput,
	"org.aspectj.lang.ProceedingJoinPoint": taint.SrcUserInput,

	// Micronaut HttpRequest. Quarkus / RESTEasy Reactive use JAX-RS
	// ContainerRequestContext (already in javaTypeCatalog).
	"io.micronaut.http.HttpRequest": taint.SrcUserInput,

	// Vert.x RoutingContext / HttpServerRequest — the framework-level
	// handler types behind Vert.x Web (Quarkus's HTTP layer is Vert.x).
	"io.vertx.ext.web.RoutingContext":   taint.SrcUserInput,
	"io.vertx.core.http.HttpServerRequest": taint.SrcUserInput,

	// Apache Camel — Exchange and Message are the standard inbound
	// taint boundaries inside @Handler / @Consume Camel beans. The
	// java_sources catalog already has receiver-anchored sinks/sources
	// for these (java.camel.exchange.getin etc.); adding the
	// parameter-typed shape lets cross-file analysis pick up `void
	// process(Exchange exchange)` handlers.
	"org.apache.camel.Exchange": taint.SrcExternal,
	"org.apache.camel.Message":  taint.SrcExternal,
}

func init() {
	// Merge the framework extras into the existing javaTypeCatalog so
	// downstream lookups (LookupSource / LookupSourceReturn) see one
	// unified map. We do this here rather than inlining into the
	// extractor_java.go literal to keep this file as the single source
	// of truth for framework-aware extensions.
	for k, v := range javaTypeCatalogFrameworkExtras {
		javaTypeCatalog.SourceParam[k] = v
	}
}
