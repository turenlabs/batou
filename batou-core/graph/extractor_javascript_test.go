package graph

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestJSExtractor_Registered confirms init() wired both JavaScript and
// TypeScript extractors into the registry.
func TestJSExtractor_Registered(t *testing.T) {
	if !IsExtractorSupported(rules.LangJavaScript) {
		t.Fatal("JavaScript extractor not registered")
	}
	if !IsExtractorSupported(rules.LangTypeScript) {
		t.Fatal("TypeScript extractor not registered")
	}
}

// TestJSExtractor_FunctionDeclaration covers the simplest shape:
// `function name(...) { ... }`.
func TestJSExtractor_FunctionDeclaration(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "fn_decl_with_two_params",
			FilePath: "/app/handler.js",
			Content: `function handler(req, res) {
  return res.send(req.body);
}
`,
			Func: "handler",
			WantParams: []ParamTaint{
				{Index: 0, Name: "req"},
				{Index: 1, Name: "res"},
			},
		},
		{
			Name:     "async_fn_decl",
			FilePath: "/app/h.js",
			Content: `async function handler(req) {
  return await req.json();
}
`,
			Func: "handler",
			WantParams: []ParamTaint{
				{Index: 0, Name: "req"},
			},
		},
	}
	RunHarness(t, rules.LangJavaScript, cases)
}

// TestJSExtractor_ArrowAssignedToConst covers `const name = (...) => {}`.
func TestJSExtractor_ArrowAssignedToConst(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "const_arrow",
			FilePath: "/app/h.js",
			Content: `const handler = (req, res) => {
  return res.send(req.body);
};
`,
			Func: "handler",
			WantParams: []ParamTaint{
				{Index: 0, Name: "req"},
				{Index: 1, Name: "res"},
			},
		},
		{
			Name:     "const_async_arrow",
			FilePath: "/app/h.js",
			Content: `const handler = async (req) => {
  return await req.json();
};
`,
			Func: "handler",
			WantParams: []ParamTaint{
				{Index: 0, Name: "req"},
			},
		},
		{
			Name:     "const_function_expression",
			FilePath: "/app/h.js",
			Content: `const handler = function (req) {
  return req.body;
};
`,
			Func: "handler",
			WantParams: []ParamTaint{
				{Index: 0, Name: "req"},
			},
		},
	}
	RunHarness(t, rules.LangJavaScript, cases)
}

// TestJSExtractor_ClassMethod covers methods on classes — names are
// qualified with the class name.
func TestJSExtractor_ClassMethod(t *testing.T) {
	src := `class UserController {
  async getUser(req, res) {
    return res.json({user: req.user});
  }
  static helper(x) {
    return x;
  }
}
`
	ex := GetExtractor(rules.LangJavaScript)
	if ex == nil {
		t.Fatal("no JS extractor")
	}
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/ctrl.js",
		Content:  []byte(src),
		Language: rules.LangJavaScript,
	})
	names := map[string]bool{}
	for _, s := range sigs {
		names[s.Name] = true
	}
	for _, want := range []string{"UserController.getUser", "UserController.helper"} {
		if !names[want] {
			t.Errorf("missing signature %q in %v", want, names)
		}
	}
}

// TestJSExtractor_ObjectLiteralMethod: `const ctrl = { foo: () => {}, bar() {} }`
// yields "ctrl.foo" and "ctrl.bar".
func TestJSExtractor_ObjectLiteralMethod(t *testing.T) {
	src := `const ctrl = {
  getUser: async (req) => req.user,
  helper(x) { return x; }
};
`
	ex := GetExtractor(rules.LangJavaScript)
	if ex == nil {
		t.Fatal("no JS extractor")
	}
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/c.js",
		Content:  []byte(src),
		Language: rules.LangJavaScript,
	})
	names := map[string]bool{}
	for _, s := range sigs {
		names[s.Name] = true
	}
	for _, want := range []string{"ctrl.getUser", "ctrl.helper"} {
		if !names[want] {
			t.Errorf("missing signature %q in %v", want, names)
		}
	}
}

// TestJSExtractor_ESMExports covers `export function`, `export const`,
// and `export default function`.
func TestJSExtractor_ESMExports(t *testing.T) {
	src := `export function exportedFn(req) { return req.body; }
export const exportedArrow = (req) => req.body;
export default function (req) { return req.body; }
`
	ex := GetExtractor(rules.LangJavaScript)
	if ex == nil {
		t.Fatal("no JS extractor")
	}
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/e.js",
		Content:  []byte(src),
		Language: rules.LangJavaScript,
	})
	names := map[string]bool{}
	for _, s := range sigs {
		names[s.Name] = true
	}
	for _, want := range []string{"exportedFn", "exportedArrow", "default"} {
		if !names[want] {
			t.Errorf("missing signature %q in %v", want, names)
		}
	}
}

// TestJSExtractor_CommonJSExports covers `module.exports.X = ...` /
// `exports.X = ...` / `module.exports = ...` (default).
func TestJSExtractor_CommonJSExports(t *testing.T) {
	src := `module.exports = function (req) { return req.body; };
module.exports.handler = function (req) { return req.body; };
exports.other = function (req) { return req.body; };
`
	ex := GetExtractor(rules.LangJavaScript)
	if ex == nil {
		t.Fatal("no JS extractor")
	}
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/cj.js",
		Content:  []byte(src),
		Language: rules.LangJavaScript,
	})
	names := map[string]bool{}
	for _, s := range sigs {
		names[s.Name] = true
	}
	for _, want := range []string{"default", "handler", "other"} {
		if !names[want] {
			t.Errorf("missing signature %q in %v", want, names)
		}
	}
}

// TestJSExtractor_TypeScriptTypedParams: TS-specific shapes with type
// annotations on parameters parse and yield Type fields populated.
func TestJSExtractor_TypeScriptTypedParams(t *testing.T) {
	ex := GetExtractor(rules.LangTypeScript)
	if ex == nil {
		t.Fatal("no TS extractor")
	}
	src := `function handler(req: Request, res: Response): Promise<void> {
  return res.send(req.body);
}
`
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/h.ts",
		Content:  []byte(src),
		Language: rules.LangTypeScript,
	})
	var got *FuncSignature
	for i := range sigs {
		if sigs[i].Name == "handler" {
			got = &sigs[i]
			break
		}
	}
	if got == nil {
		t.Fatal("handler not extracted")
	}
	if len(got.Params) != 2 {
		t.Fatalf("expected 2 params, got %d (%+v)", len(got.Params), got.Params)
	}
	if got.Params[0].Name != "req" {
		t.Errorf("Params[0].Name = %q, want req", got.Params[0].Name)
	}
	if got.Params[0].Type == "" {
		t.Errorf("Params[0].Type = %q, want non-empty (TS annotation)", got.Params[0].Type)
	}
	if got.Params[1].Name != "res" {
		t.Errorf("Params[1].Name = %q, want res", got.Params[1].Name)
	}
}

// TestJSExtractor_TypeScriptGenericFn: TS function with a generic type
// parameter — the body parses correctly and params are extracted.
func TestJSExtractor_TypeScriptGenericFn(t *testing.T) {
	ex := GetExtractor(rules.LangTypeScript)
	if ex == nil {
		t.Fatal("no TS extractor")
	}
	src := `function handler<T>(req: Request, ...rest: string[]): Promise<T> {
  return null as any;
}
`
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/g.ts",
		Content:  []byte(src),
		Language: rules.LangTypeScript,
	})
	var got *FuncSignature
	for i := range sigs {
		if sigs[i].Name == "handler" {
			got = &sigs[i]
			break
		}
	}
	if got == nil {
		t.Fatal("generic handler not extracted")
	}
	if len(got.Params) < 2 {
		t.Fatalf("expected 2 params, got %d (%+v)", len(got.Params), got.Params)
	}
	if got.Params[0].Name != "req" {
		t.Errorf("Params[0].Name = %q, want req", got.Params[0].Name)
	}
	if got.Params[1].Name != "rest" {
		t.Errorf("Params[1].Name = %q, want rest (rest param)", got.Params[1].Name)
	}
}

// TestJSExtractor_DefaultAndDestructuredParams verifies that default
// values and destructuring at the parameter position don't crash the
// walker. We don't try to name destructured bindings — the index counter
// just needs to stay accurate.
func TestJSExtractor_DefaultAndDestructuredParams(t *testing.T) {
	ex := GetExtractor(rules.LangJavaScript)
	if ex == nil {
		t.Fatal("no JS extractor")
	}
	src := `function handler(req, {body, headers}, opts = {}) {
  return body;
}
`
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/d.js",
		Content:  []byte(src),
		Language: rules.LangJavaScript,
	})
	var got *FuncSignature
	for i := range sigs {
		if sigs[i].Name == "handler" {
			got = &sigs[i]
			break
		}
	}
	if got == nil {
		t.Fatal("handler not extracted")
	}
	// 3 params total: req, {destructured}, opts.
	if len(got.Params) != 3 {
		t.Fatalf("expected 3 params, got %d (%+v)", len(got.Params), got.Params)
	}
	if got.Params[0].Name != "req" {
		t.Errorf("Params[0].Name = %q, want req", got.Params[0].Name)
	}
	if got.Params[2].Name != "opts" {
		t.Errorf("Params[2].Name = %q, want opts (default param)", got.Params[2].Name)
	}
}

// TestJSExtractor_EmptyFile is the defensive test — empty input must not
// crash and must return zero signatures.
func TestJSExtractor_EmptyFile(t *testing.T) {
	ex := GetExtractor(rules.LangJavaScript)
	if ex == nil {
		t.Fatal("no JS extractor")
	}
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/empty.js",
		Content:  []byte("// just a comment\nconst x = 1;\n"),
		Language: rules.LangJavaScript,
	})
	if len(sigs) != 0 {
		t.Errorf("expected 0 signatures for empty-ish file, got %d (%+v)", len(sigs), sigs)
	}
}

// TestJSExtractor_NilContext: nil ExtractContext must return empty.
func TestJSExtractor_NilContext(t *testing.T) {
	ex := GetExtractor(rules.LangJavaScript)
	if ex == nil {
		t.Fatal("no JS extractor")
	}
	sigs := ex.ExtractFunctions(nil)
	if len(sigs) != 0 {
		t.Errorf("expected nil-safe behavior, got %d signatures", len(sigs))
	}
}

// TestJSExtractor_ExpressHandlerSourceParam_NameHeuristic verifies the
// PR-BBjs name-based framework-handler heuristic tags `(req, res)` as
// having `req` marked as a SrcUserInput parameter even without any TS
// annotation.
func TestJSExtractor_ExpressHandlerSourceParam_NameHeuristic(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "arrow_req_res",
			FilePath: "/app/h.js",
			Content: `const handler = (req, res) => {
  return res.send(req.body);
};
`,
			Func: "handler",
			WantParams: []ParamTaint{
				{Index: 0, Name: "req", IsSourceType: true, SourceCategory: taint.SrcUserInput},
				{Index: 1, Name: "res"},
			},
		},
		{
			Name:     "fn_decl_req_res_next",
			FilePath: "/app/m.js",
			Content: `function middleware(req, res, next) {
  next();
}
`,
			Func: "middleware",
			WantParams: []ParamTaint{
				{Index: 0, Name: "req", IsSourceType: true, SourceCategory: taint.SrcUserInput},
				{Index: 1, Name: "res"},
				{Index: 2, Name: "next"},
			},
		},
		{
			Name:     "fastify_request_reply",
			FilePath: "/app/f.js",
			Content: `const handler = async (request, reply) => {
  return reply.send({body: request.body});
};
`,
			Func: "handler",
			WantParams: []ParamTaint{
				{Index: 0, Name: "request", IsSourceType: true, SourceCategory: taint.SrcUserInput},
				{Index: 1, Name: "reply"},
			},
		},
		{
			Name:     "hapi_request_h",
			FilePath: "/app/hapi.js",
			Content: `const handler = (request, h) => {
  return h.response(request.payload);
};
`,
			Func: "handler",
			WantParams: []ParamTaint{
				{Index: 0, Name: "request", IsSourceType: true, SourceCategory: taint.SrcUserInput},
				{Index: 1, Name: "h"},
			},
		},
	}
	RunHarness(t, rules.LangJavaScript, cases)
}

// TestJSExtractor_KoaHandlerSourceParam_NameHeuristic verifies that
// Koa/Lambda-style bare-context parameters are NOT tagged as sources
// by the framework-handler name heuristic.
//
// PR-CATjs-3 removed the single-arg `(ctx)` / `(ctx, next)` /
// `(event, context)` shapes from the heuristic because tagging the
// receiver itself produced FPs (every `ctx.set('foo', 'literal')` /
// `c.json({ok: true})` / `reply.send('ok')` was treated as a
// source-to-sink flow). The regex source catalog still fires at the
// actual access sites (`ctx.request.body`, `ctx.query`, `c.req.json()`,
// `event.url.searchParams`), so no real-world detections are lost.
func TestJSExtractor_KoaHandlerSourceParam_NameHeuristic(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "single_ctx_not_tagged",
			FilePath: "/app/k.js",
			Content: `const handler = async ctx => {
  ctx.body = ctx.query.q;
};
`,
			Func: "handler",
			WantParams: []ParamTaint{
				{Index: 0, Name: "ctx"},
			},
		},
		{
			Name:     "ctx_next_middleware_not_tagged",
			FilePath: "/app/k2.js",
			Content: `const mw = async (ctx, next) => {
  await next();
  ctx.body = 'ok';
};
`,
			Func: "mw",
			WantParams: []ParamTaint{
				{Index: 0, Name: "ctx"},
				{Index: 1, Name: "next"},
			},
		},
		{
			Name:     "lambda_event_context_not_tagged",
			FilePath: "/app/lambda.js",
			Content: `exports.handler = async (event, context) => {
  return { statusCode: 200, body: event.body };
};
`,
			Func: "handler",
			WantParams: []ParamTaint{
				{Index: 0, Name: "event"},
				{Index: 1, Name: "context"},
			},
		},
	}
	RunHarness(t, rules.LangJavaScript, cases)
}

// TestJSExtractor_TypedRequestParam_TSCatalog verifies the PR-BBjs
// TypeScript catalog tags a parameter typed as `Request` /
// `NextApiRequest` / `FastifyRequest` as a source.
func TestJSExtractor_TypedRequestParam_TSCatalog(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "express_request_typed",
			FilePath: "/app/h.ts",
			Content: `function handler(req: Request, res: Response): void {
  res.send(req.body);
}
`,
			Func: "handler",
			WantParams: []ParamTaint{
				{Index: 0, Name: "req", CanonicalType: "Request", IsSourceType: true, SourceCategory: taint.SrcUserInput},
				{Index: 1, Name: "res"},
			},
		},
		{
			Name:     "nextapirequest_typed",
			FilePath: "/app/n.ts",
			Content: `function handler(req: NextApiRequest, res: NextApiResponse): void {
  res.json({body: req.body});
}
`,
			Func: "handler",
			WantParams: []ParamTaint{
				{Index: 0, Name: "req", CanonicalType: "NextApiRequest", IsSourceType: true, SourceCategory: taint.SrcUserInput},
				{Index: 1, Name: "res"},
			},
		},
		{
			Name:     "fastifyrequest_with_generic",
			FilePath: "/app/f.ts",
			Content: `function handler(request: FastifyRequest<{ Body: { x: string } }>, reply: FastifyReply): void {
  reply.send(request.body);
}
`,
			Func: "handler",
			WantParams: []ParamTaint{
				{Index: 0, Name: "request", CanonicalType: "FastifyRequest", IsSourceType: true, SourceCategory: taint.SrcUserInput},
				{Index: 1, Name: "reply"},
			},
		},
	}
	RunHarness(t, rules.LangTypeScript, cases)
}

// TestJSTypeCatalog_FrameworkRequestTypes pins the core catalog entries
// that downstream interproc analysis depends on.
func TestJSTypeCatalog_FrameworkRequestTypes(t *testing.T) {
	cat := JavaScriptTypeCatalog()
	if cat == nil {
		t.Fatal("JavaScriptTypeCatalog() returned nil")
	}
	for _, name := range []string{"Request", "NextApiRequest", "NextRequest", "FastifyRequest", "Context", "RequestEvent"} {
		got, ok := cat.LookupSource(name)
		if !ok {
			t.Errorf("JS type catalog: %q not in SourceParam map", name)
			continue
		}
		if got != taint.SrcUserInput {
			t.Errorf("JS type catalog: %q category = %q, want SrcUserInput", name, got)
		}
	}
}

// TestJSCanonicalizeJSType verifies the type-annotation normaliser
// strips generics, union heads, and array suffixes.
func TestJSCanonicalizeJSType(t *testing.T) {
	cases := map[string]string{
		"Request":           "Request",
		"Request<{}>":       "Request",
		"FastifyRequest<X>": "FastifyRequest",
		"Request | null":    "Request",
		"Request[]":         "Request",
		" : Request ":       "Request",
		"":                  "",
	}
	for in, want := range cases {
		got := canonicalizeJSType(in)
		if got != want {
			t.Errorf("canonicalizeJSType(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestJSFrameworkHandlerCategory_NameHeuristic_Negatives verifies the
// heuristic does NOT tag unrelated parameter shapes — including the
// bare-context/event shapes PR-CATjs-3 removed because they produced
// FPs in real-world scans.
func TestJSFrameworkHandlerCategory_NameHeuristic_Negatives(t *testing.T) {
	negatives := [][]ParamTaint{
		{{Index: 0, Name: "x"}, {Index: 1, Name: "y"}},           // (x, y) — arbitrary
		{{Index: 0, Name: "foo"}, {Index: 1, Name: "bar"}},       // (foo, bar)
		{{Index: 0, Name: "config"}, {Index: 1, Name: "opts"}},   // (config, opts)
		{{Index: 0, Name: "data"}, {Index: 1, Name: "callback"}}, // (data, callback)

		// PR-CATjs-3: the bare-context single-arg shapes used to match
		// and tag the param itself as a source. The regex catalog covers
		// the actual access patterns (`ctx.query`, `c.req.json()`, etc.)
		// so the name-only tagging caused FPs without recall benefit.
		{{Index: 0, Name: "ctx"}},     // Koa single-arg
		{{Index: 0, Name: "context"}}, // generic context
		{{Index: 0, Name: "c"}},       // Hono shorthand
		{{Index: 0, Name: "event"}},   // Lambda / SvelteKit single-arg

		// (ctx, next) — Koa middleware. Source detection now relies on
		// ctx.X regex patterns at access sites, not param-name tagging.
		{{Index: 0, Name: "ctx"}, {Index: 1, Name: "next"}},
		// (event, context) — AWS Lambda handler.
		{{Index: 0, Name: "event"}, {Index: 1, Name: "context"}},
	}
	for i, params := range negatives {
		_, _, ok := jsFrameworkHandlerCategory(params)
		if ok {
			t.Errorf("case %d: expected NO match for %+v, got match", i, params)
		}
	}
}

// TestJSFrameworkHandlerCategory_NameHeuristic_ResNotSource is the
// PR-CATjs-3 regression guard: the response-shaped param in a (req, res)
// pair must never be returned as the source index. Only req (idx 0) is
// the source.
func TestJSFrameworkHandlerCategory_NameHeuristic_ResNotSource(t *testing.T) {
	cases := []struct {
		name   string
		params []ParamTaint
		want   int // expected paramIndex
	}{
		{
			name:   "express_req_res",
			params: []ParamTaint{{Index: 0, Name: "req"}, {Index: 1, Name: "res"}},
			want:   0,
		},
		{
			name:   "express_request_response",
			params: []ParamTaint{{Index: 0, Name: "request"}, {Index: 1, Name: "response"}},
			want:   0,
		},
		{
			name:   "fastify_request_reply",
			params: []ParamTaint{{Index: 0, Name: "request"}, {Index: 1, Name: "reply"}},
			want:   0,
		},
		{
			name:   "express_mw_req_res_next",
			params: []ParamTaint{{Index: 0, Name: "req"}, {Index: 1, Name: "res"}, {Index: 2, Name: "next"}},
			want:   0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idx, cat, ok := jsFrameworkHandlerCategory(tc.params)
			if !ok {
				t.Fatalf("expected match for %+v, got none", tc.params)
			}
			if idx != tc.want {
				t.Errorf("idx=%d (param %q) want %d (param %q)",
					idx, tc.params[idx].Name, tc.want, tc.params[tc.want].Name)
			}
			if cat != taint.SrcUserInput {
				t.Errorf("category=%q want SrcUserInput", cat)
			}
			// The response-shaped param must NOT be the returned index.
			respNames := map[string]bool{"res": true, "response": true, "reply": true, "h": true}
			if respNames[tc.params[idx].Name] {
				t.Errorf("returned idx=%d points to response-shaped param %q",
					idx, tc.params[idx].Name)
			}
		})
	}
}


// TestJSExtractor_CustomInterfaceParam_SuppressesNameHeuristic verifies
// that PR-CATjs-6 prevents the name-based framework-handler heuristic
// from firing when a candidate param carries a TS type annotation that
// is NOT in the framework catalog and is NOT a primitive (i.e. a
// project-defined interface like n8n's `IRestApiContext`). The catalog-
// matched cases (`Request`, `Context`, `FastifyRequest`, …) and the
// primitive/untyped cases must still be tagged.
func TestJSExtractor_CustomInterfaceParam_SuppressesNameHeuristic(t *testing.T) {
	type expect struct {
		isSourceTagged bool
		paramIdx       int
	}
	cases := []struct {
		name     string
		filePath string
		content  string
		fn       string
		want     expect
	}{
		// --- POSITIVE: framework-catalog types still source-tag.
		{
			name:     "express_request_typed_still_tagged",
			filePath: "/app/h.ts",
			content: `function handler(req: Request, res: Response): void {
  res.send(req.body);
}
`,
			fn:   "handler",
			want: expect{isSourceTagged: true, paramIdx: 0},
		},
		{
			name:     "nextjs_request_typed_still_tagged",
			filePath: "/app/n.ts",
			content: `function handler(req: NextApiRequest, res: NextApiResponse): void {
  res.json({body: req.body});
}
`,
			fn:   "handler",
			want: expect{isSourceTagged: true, paramIdx: 0},
		},
		{
			name:     "koa_context_typed_still_tagged",
			filePath: "/app/k.ts",
			content: `async function handler(ctx: Context) {
  ctx.body = ctx.query.q;
}
`,
			fn:   "handler",
			want: expect{isSourceTagged: true, paramIdx: 0},
		},
		{
			name:     "fastify_request_typed_still_tagged",
			filePath: "/app/f.ts",
			content: `function handler(request: FastifyRequest, reply: FastifyReply): void {
  reply.send(request.body);
}
`,
			fn:   "handler",
			want: expect{isSourceTagged: true, paramIdx: 0},
		},
		// --- POSITIVE: primitive-typed `req` in a (req, res) pair keeps
		// the name heuristic. `(req: string, res: any)` is loose
		// TypeScript that still matches the Express shape — the guard
		// only suppresses when the annotation is a project-defined
		// interface, not a primitive. Uses the two-arg req/res shape
		// (single-arg `event`/`ctx`/`c` heuristics were dropped by
		// PR-CATjs-3).
		{
			name:     "primitive_typed_still_tagged_by_name",
			filePath: "/app/p.ts",
			content: `function handler(req: string, res: any) {
  return req;
}
`,
			fn:   "handler",
			want: expect{isSourceTagged: true, paramIdx: 0},
		},
		// --- POSITIVE: generic type variable behaves like a primitive.
		{
			name:     "generic_T_still_tagged_by_name",
			filePath: "/app/g.ts",
			content: `function handler<T>(req: T, res: any) {
  return req;
}
`,
			fn:   "handler",
			want: expect{isSourceTagged: true, paramIdx: 0},
		},
		// --- POSITIVE: plain (untyped) JS params retain heuristic.
		{
			name:     "untyped_js_still_tagged",
			filePath: "/app/u.js",
			content: `function handler(req, res) {
  return req;
}
`,
			fn:   "handler",
			want: expect{isSourceTagged: true, paramIdx: 0},
		},
		// --- NEGATIVE: project-defined interface suppresses the heuristic.
		// This is the n8n IRestApiContext case — the param name "context"
		// would otherwise match jsFrameworkHandlerCategory.
		{
			name:     "custom_interface_irestapicontext_not_tagged",
			filePath: "/app/n8n.ts",
			content: `function fetchData(context: IRestApiContext) {
  return fetch(context.baseUrl);
}
`,
			fn:   "fetchData",
			want: expect{isSourceTagged: false},
		},
		{
			name:     "custom_interface_workflowconfig_not_tagged",
			filePath: "/app/w.ts",
			content: `function process(ctx: WorkflowConfig) {
  return ctx.value;
}
`,
			fn:   "process",
			want: expect{isSourceTagged: false},
		},
		// Two-arg variant: a custom-typed first param still suppresses.
		{
			name:     "custom_interface_two_arg_not_tagged",
			filePath: "/app/w2.ts",
			content: `function handler(req: MyRequest, res: MyResponse) {
  return res.send(req.body);
}
`,
			fn:   "handler",
			want: expect{isSourceTagged: false},
		},
		// `(event: LambdaCustomEvent)` — name matches the single-arg
		// `event` shape but the type is a custom interface.
		{
			name:     "custom_interface_event_not_tagged",
			filePath: "/app/e.ts",
			content: `function handle(event: MyDomainEvent) {
  return event.payload;
}
`,
			fn:   "handle",
			want: expect{isSourceTagged: false},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			lang := rules.LangTypeScript
			if strings.HasSuffix(tc.filePath, ".js") {
				lang = rules.LangJavaScript
			}
			ex := GetExtractor(lang)
			if ex == nil {
				t.Fatalf("no extractor for %q", lang)
			}
			sigs := ex.ExtractFunctions(&ExtractContext{
				FilePath: tc.filePath,
				Content:  []byte(tc.content),
				Language: lang,
			})
			sig := findSignature(sigs, tc.fn)
			if sig == nil {
				t.Fatalf("no signature for %q; got %d sigs", tc.fn, len(sigs))
			}
			if tc.want.isSourceTagged {
				if tc.want.paramIdx >= len(sig.Params) {
					t.Fatalf("expected param[%d] but only %d params", tc.want.paramIdx, len(sig.Params))
				}
				p := sig.Params[tc.want.paramIdx]
				if !p.IsSourceType {
					t.Errorf("Params[%d].IsSourceType = false, want true (params=%+v)", tc.want.paramIdx, sig.Params)
				}
				if p.SourceCategory != taint.SrcUserInput {
					t.Errorf("Params[%d].SourceCategory = %q, want %q", tc.want.paramIdx, p.SourceCategory, taint.SrcUserInput)
				}
			} else {
				for i, p := range sig.Params {
					if p.IsSourceType {
						t.Errorf("Params[%d] = %+v: IsSourceType=true, want false (custom interface should suppress name heuristic)", i, p)
					}
				}
			}
		})
	}
}

// TestJSParamHasCustomTypeAnnotation pins the helper's classification
// of TS annotations into "primitive/generic/untyped" (heuristic OK to
// fire) versus "project-defined interface" (heuristic must be skipped).
func TestJSParamHasCustomTypeAnnotation(t *testing.T) {
	cases := []struct {
		canonical string
		want      bool
	}{
		// Untyped / primitives / generics — heuristic should fire.
		{"", false},
		{"string", false},
		{"number", false},
		{"boolean", false},
		{"any", false},
		{"unknown", false},
		{"void", false},
		{"T", false},
		{"U", false},
		{"TKey", false},
		{"TValue", false},
		// Project-defined interfaces — heuristic must be suppressed.
		{"IRestApiContext", true},
		{"MyRequest", true},
		{"WorkflowConfig", true},
		{"Foo.Bar.Baz", true},
		{"Custom", true},
	}
	for _, c := range cases {
		got := jsParamHasCustomTypeAnnotation(ParamTaint{CanonicalType: c.canonical})
		if got != c.want {
			t.Errorf("jsParamHasCustomTypeAnnotation({CanonicalType:%q}) = %v, want %v", c.canonical, got, c.want)
		}
	}
}
