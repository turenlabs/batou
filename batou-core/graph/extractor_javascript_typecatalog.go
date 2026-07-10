// JavaScript / TypeScript framework type catalog and handler-name
// heuristics for the cross-file graph extractor.
//
// Mirrors batou-core/graph/extractor_python.go's pythonTypeCatalog and
// extractor_java.go's javaTypeCatalog, with two adaptations specific to
// JS:
//
//  1. TypeScript type annotations are recognised by *short name* (e.g.
//     `Request`, `NextApiRequest`, `FastifyRequest`, `KoaContext`),
//     because we don't resolve `import { Request } from "express"` →
//     `express.Request` the way the Python extractor follows
//     `from flask import Request` → `flask.Request`. JS imports are
//     module-as-namespace, not class-as-namespace, so the FQN story is
//     materially weaker. Short-name matching is acceptable for SAST
//     because the framework types are well-known and rarely collide.
//
//  2. Plain JavaScript (no TS annotations at all) is handled by a
//     *parameter-name + position* heuristic: when a function has a
//     two-parameter shape that looks like `(req, res)`, `(request, reply)`,
//     `(ctx, next)`, etc., the request-side parameter is tagged as a
//     SrcUserInput source. This is the Express/Koa/Fastify convention;
//     it covers the dominant real-world Node code path. Closures
//     registered via `app.get(...)` / `router.use(...)` callbacks usually
//     match these naming conventions.
//
// What this catalog does NOT do (documented as future work):
//
//   - Resolve NestJS @Body / @Query / @Param decorators on individual
//     parameters. NestJS parameter decorators live in the decorator
//     node's `arguments` field; correctly attributing them to the right
//     positional param requires walking the parameter's leading
//     decorators, which is non-trivial in tree-sitter (decorators sit
//     above the parameter in the formal_parameters list and the grammar
//     attaches them as siblings, not children). The js.nestjs.* regex
//     catalog entries already match the decorator usage site; the
//     interprocedural extractor falls back to that for now.
//
//   - Handle `app.use(middleware)` middleware functions vs. handler
//     functions distinctly. We treat both as `(req, res, next)` shape.
//
//   - Recognise Apollo Server / GraphQL resolver param shapes
//     `(parent, args, context, info)` — handled by the regex
//     `js.graphql.resolver.args` source.
package graph

import (
	"strings"

	"github.com/turenlabs/batou-core/taint"
)

// javascriptTypeCatalog enumerates the canonical framework Request /
// Context types that should be treated as taint sources when seen as a
// parameter type in a TypeScript file. Keys are the short type name as
// it appears in the source (the JS extractor does NOT FQN-canonicalise).
var javascriptTypeCatalog = &TypeCatalog{
	SourceParam: map[string]taint.SourceCategory{
		// Express
		"Request":         taint.SrcUserInput,
		"express.Request": taint.SrcUserInput,
		"Express.Request": taint.SrcUserInput,

		// Next.js
		"NextApiRequest":  taint.SrcUserInput,
		"NextRequest":     taint.SrcUserInput,
		"GetServerSidePropsContext": taint.SrcUserInput,

		// Fastify
		"FastifyRequest": taint.SrcUserInput,

		// Koa
		"Context":        taint.SrcUserInput,
		"Koa.Context":    taint.SrcUserInput,
		"ParameterizedContext": taint.SrcUserInput,
		"RouterContext":  taint.SrcUserInput,

		// Hapi
		"Request_2":      taint.SrcUserInput, // hapi internal
		"Hapi.Request":   taint.SrcUserInput,

		// Hono
		"HonoContext":    taint.SrcUserInput,
		"Context_2":      taint.SrcUserInput,

		// SvelteKit / Remix / Astro
		"RequestEvent":   taint.SrcUserInput,
		"LoaderArgs":     taint.SrcUserInput,
		"ActionArgs":     taint.SrcUserInput,

		// AWS Lambda
		"APIGatewayProxyEvent":   taint.SrcUserInput,
		"APIGatewayProxyEventV2": taint.SrcUserInput,
		"APIGatewayEvent":        taint.SrcUserInput,
		"LambdaEvent":            taint.SrcUserInput,

		// H3 / Nuxt
		"H3Event":        taint.SrcUserInput,
		"H3EventContext": taint.SrcUserInput,
	},
	SinkParam: map[string]taint.SinkCategory{
		// (none — JS sinks aren't typically tracked via parameter types)
	},
	SourceReturn: map[string]taint.SourceCategory{
		"Request":        taint.SrcUserInput,
		"NextApiRequest": taint.SrcUserInput,
		"NextRequest":    taint.SrcUserInput,
		"FastifyRequest": taint.SrcUserInput,
	},
}

// JavaScriptTypeCatalog returns the JS/TS type catalog. Exposed for
// tests and follow-up PRs that want to extend the framework coverage.
func JavaScriptTypeCatalog() *TypeCatalog { return javascriptTypeCatalog }

// canonicalizeJSType normalises a raw TS type annotation by stripping
// generics, optionals, and surrounding whitespace. The JS extractor
// does NOT follow imports to FQN-canonicalise — see the package
// comment for why.
//
//	"Request"          → "Request"
//	"Request<{}>"      → "Request"
//	"FastifyRequest<…>"→ "FastifyRequest"
//	"Express.Request"  → "Express.Request"   (kept; dotted refs match catalog)
//	"Request | null"   → "Request"           (union — first head only)
func canonicalizeJSType(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Strip leading '?' (optional marker rarely shows up here, but be safe).
	raw = strings.TrimPrefix(raw, "?")
	// Drop the colon that some grammars include in the type field text.
	raw = strings.TrimPrefix(raw, ":")
	raw = strings.TrimSpace(raw)
	// Union / intersection: take the first head.
	if i := strings.IndexAny(raw, "|&"); i >= 0 {
		raw = strings.TrimSpace(raw[:i])
	}
	// Strip generics.
	if i := strings.IndexByte(raw, '<'); i >= 0 {
		raw = strings.TrimSpace(raw[:i])
	}
	// Strip array suffix.
	raw = strings.TrimSuffix(raw, "[]")
	return strings.TrimSpace(raw)
}

// jsFrameworkHandlerCategory inspects a function's positional parameter
// names and returns (paramIndex, category, true) when the shape matches a
// known framework handler convention. Returns (-1, "", false) otherwise.
//
// The recognised shapes are:
//
//	(req, res)               — Express / Connect / Restify / Next.js Pages
//	(req, res, next)         — Express middleware
//	(request, reply)         — Fastify
//	(request, h)             — Hapi
//	(err, req, res)          — Express error middleware (req at idx 1)
//
// When multiple parameters match (e.g. (req, res) — req is the source,
// res is the response), the returned paramIndex points to the
// request-side parameter. The response is intentionally not tagged
// because writes to `res` are sinks, not sources — and the regex sink
// catalog already covers `res.send(req.body)` shapes.
//
// PR-CATjs-3: removed the single-arg `(ctx)` / `(context)` / `(event)` /
// `(c)` shapes and the `(ctx, next)` Koa middleware / `(event, context)`
// AWS Lambda shapes. Tagging the *bare* context/event/reply parameter
// produced FPs in real-world scans — every `ctx.set(...)` / `c.json(...)`
// / `reply.send(...)` call where the argument referenced the bare
// receiver was treated as a source-to-sink flow even when the argument
// was a literal. The regex source catalog already covers the actual
// user-input access patterns (`ctx.request.body`, `ctx.query`,
// `c.req.json()`, `event.url.searchParams`, etc.), so dropping the
// param-name shorthand loses no real detections while killing the FPs.
//
// This is a pure-name heuristic. False positives (a function whose
// parameter happens to be named `req` but isn't actually a handler) are
// rare in real Node code because the `req`/`request` convention is so
// strongly associated with HTTP handlers. False negatives (handlers
// using non-conventional names like `httpRequest`) are tolerable —
// tsflow's existing per-line regex catalog still picks up `req.body` /
// `request.params` accesses inside the function body.
func jsFrameworkHandlerCategory(params []ParamTaint) (int, taint.SourceCategory, bool) {
	if len(params) == 0 {
		return -1, "", false
	}
	first := strings.ToLower(strings.TrimSpace(params[0].Name))
	switch len(params) {
	case 2:
		second := strings.ToLower(strings.TrimSpace(params[1].Name))
		// (req, res) — Express/Connect/Restify, Next.js Pages API route,
		// Fastify (request, reply), Hapi (request, h).
		if (first == "req" || first == "request") &&
			(second == "res" || second == "response" || second == "reply" || second == "h") {
			return 0, taint.SrcUserInput, true
		}
	case 3:
		second := strings.ToLower(strings.TrimSpace(params[1].Name))
		third := strings.ToLower(strings.TrimSpace(params[2].Name))
		// (req, res, next) — Express middleware.
		if (first == "req" || first == "request") &&
			(second == "res" || second == "response") &&
			third == "next" {
			return 0, taint.SrcUserInput, true
		}
		// (err, req, res) — Express error middleware: still mark req.
		if first == "err" && (second == "req" || second == "request") &&
			(third == "res" || third == "response") {
			return 1, taint.SrcUserInput, true
		}
	}
	return -1, "", false
}
