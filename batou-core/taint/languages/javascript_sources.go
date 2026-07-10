package languages

import (
	"github.com/turenlabs/batou-core/taint"

	"github.com/turenlabs/batou-rules/rules"
)

// jsSources defines taint sources for JavaScript/TypeScript.
var jsSources = []taint.SourceDef{
	// Express request sources
	{ID: "js.express.req.query", Category: taint.SrcUserInput, Pattern: `req\.query`, ObjectType: "Request", MethodName: "query", Description: "Express request query parameters", Assigns: "return"},
	{ID: "js.express.req.params", Category: taint.SrcUserInput, Pattern: `req\.params`, ObjectType: "Request", MethodName: "params", Description: "Express request route parameters", Assigns: "return"},
	{ID: "js.express.req.body", Category: taint.SrcUserInput, Pattern: `req\.body`, ObjectType: "Request", MethodName: "body", Description: "Express request body", Assigns: "return"},
	{ID: "js.express.req.headers", Category: taint.SrcUserInput, Pattern: `req\.headers`, ObjectType: "Request", MethodName: "headers", Description: "Express request headers", Assigns: "return"},
	{ID: "js.express.req.cookies", Category: taint.SrcUserInput, Pattern: `req\.cookies`, ObjectType: "Request", MethodName: "cookies", Description: "Express request cookies", Assigns: "return"},
	{ID: "js.express.req.url", Category: taint.SrcUserInput, Pattern: `req\.url`, ObjectType: "Request", MethodName: "url", Description: "Express request URL", Assigns: "return"},
	{ID: "js.express.req.path", Category: taint.SrcUserInput, Pattern: `req\.path`, ObjectType: "Request", MethodName: "path", Description: "Express request path", Assigns: "return"},

	// Destructured Express request sources (e.g., `({ query }: Request)`)
	{ID: "js.express.destructured.query", Category: taint.SrcUserInput, Pattern: `\{\s*query\s*\}`, ObjectType: "Request", MethodName: "query", Description: "Destructured Express request query parameters", Assigns: "return"},
	{ID: "js.express.destructured.params", Category: taint.SrcUserInput, Pattern: `\{\s*params\s*\}`, ObjectType: "Request", MethodName: "params", Description: "Destructured Express request route parameters", Assigns: "return"},
	{ID: "js.express.destructured.body", Category: taint.SrcUserInput, Pattern: `\{\s*body\s*\}`, ObjectType: "Request", MethodName: "body", Description: "Destructured Express request body", Assigns: "return"},
	{ID: "js.express.destructured.file", Category: taint.SrcUserInput, Pattern: `\{\s*file\s*\}`, ObjectType: "Request", MethodName: "file", Description: "Destructured Express request file upload", Assigns: "return"},
	{ID: "js.express.destructured.cookies", Category: taint.SrcUserInput, Pattern: `\{\s*cookies\s*\}`, ObjectType: "Request", MethodName: "cookies", Description: "Destructured Express request cookies", Assigns: "return"},

	// Bare property access after destructuring (e.g., `query.foo` without `req.` prefix)
	{ID: "js.express.bare.query", Category: taint.SrcUserInput, Pattern: `\bquery\.\w+`, ObjectType: "Request", MethodName: "query", Description: "Bare query property access after destructuring", Assigns: "return"},
	{ID: "js.express.bare.params", Category: taint.SrcUserInput, Pattern: `\bparams\.\w+`, ObjectType: "Request", MethodName: "params", Description: "Bare params property access after destructuring", Assigns: "return"},
	{ID: "js.express.bare.body", Category: taint.SrcUserInput, Pattern: `\bbody\.\w+`, ObjectType: "Request", MethodName: "body", Description: "Bare body property access after destructuring", Assigns: "return"},

	// URL/Location sources.
	//
	// Removed 2026-05-12 (owncloud/web FP, CWE-918): `new URL(...)` and
	// `URLSearchParams(...)` constructors are NOT taint sources — they only
	// re-package a string. Treating the constructor as a source meant a URL
	// built entirely from admin config (`new URL('/api', config.serverUrl)`)
	// was flagged as user-tainted, producing SSRF FPs on `axios.get(url)` /
	// `fetch(url)`. Taint that is *already* on the constructor's argument
	// (e.g. `new URL(req.query.target)`) still propagates to the result via
	// the generic external-call propagation in the tsflow walker, so genuine
	// SSRF flows keep firing. The framework-specific entries below that wrap
	// `new URL(request.url).searchParams` (Remix / SvelteKit / Next.js /
	// Astro) remain — there the *argument* is the request URL, which is real
	// user input.
	{ID: "js.dom.document.location", Category: taint.SrcUserInput, Pattern: `document\.location`, ObjectType: "document", MethodName: "location", Description: "Document location (user-controlled URL)", Assigns: "return"},
	{ID: "js.dom.window.location", Category: taint.SrcUserInput, Pattern: `window\.location`, ObjectType: "window", MethodName: "location", Description: "Window location (user-controlled URL)", Assigns: "return"},
	{ID: "js.dom.location.hash", Category: taint.SrcUserInput, Pattern: `location\.hash`, ObjectType: "location", MethodName: "hash", Description: "URL hash fragment", Assigns: "return"},
	{ID: "js.dom.location.search", Category: taint.SrcUserInput, Pattern: `location\.search`, ObjectType: "location", MethodName: "search", Description: "URL query string", Assigns: "return"},

	// DOM sources
	{ID: "js.dom.document.cookie", Category: taint.SrcUserInput, Pattern: `document\.cookie`, ObjectType: "document", MethodName: "cookie", Description: "Document cookies", Assigns: "return"},
	{ID: "js.dom.getelementbyid.value", Category: taint.SrcUserInput, Pattern: `document\.getElementById\s*\([^)]*\)\s*\.value`, ObjectType: "HTMLElement", MethodName: "value", Description: "DOM element value (user input field)", Assigns: "return"},
	{ID: "js.dom.innerhtml.read", Category: taint.SrcUserInput, Pattern: `\.innerHTML(?:\s*[^=])`, ObjectType: "HTMLElement", MethodName: "innerHTML", Description: "DOM element innerHTML as input", Assigns: "return"},
	{ID: "js.dom.textcontent.read", Category: taint.SrcUserInput, Pattern: `\.textContent(?:\s*[^=])`, ObjectType: "HTMLElement", MethodName: "textContent", Description: "DOM element textContent as input", Assigns: "return"},
	{ID: "js.dom.event.target.value", Category: taint.SrcUserInput, Pattern: `event\.target\.value`, ObjectType: "Event", MethodName: "value", Description: "Event target value (React/DOM events)", Assigns: "return"},

	// CLI/env sources
	{ID: "js.process.argv", Category: taint.SrcCLIArg, Pattern: `process\.argv`, ObjectType: "process", MethodName: "argv", Description: "Command-line arguments", Assigns: "return"},
	{ID: "js.process.env", Category: taint.SrcEnvVar, Pattern: `process\.env`, ObjectType: "process", MethodName: "env", Description: "Environment variables", Assigns: "return"},

	// File sources
	{ID: "js.fs.readfilesync", Category: taint.SrcFileRead, Pattern: `fs\.readFileSync\s*\(`, ObjectType: "fs", MethodName: "readFileSync", Description: "Synchronous file read", Assigns: "return"},
	{ID: "js.fs.readfile", Category: taint.SrcFileRead, Pattern: `fs\.readFile\s*\(`, ObjectType: "fs", MethodName: "readFile", Description: "Asynchronous file read", Assigns: "return"},

	// Network sources
	{ID: "js.fetch.response", Category: taint.SrcNetwork, Pattern: `fetch\s*\(`, ObjectType: "", MethodName: "fetch", Description: "Fetch API response data", Assigns: "return"},
	{ID: "js.axios.response", Category: taint.SrcNetwork, Pattern: `axios\s*[.(]`, ObjectType: "axios", MethodName: "axios", Description: "Axios HTTP response data", Assigns: "return"},
	{ID: "js.websocket.onmessage", Category: taint.SrcNetwork, Pattern: `\.onmessage\s*=`, ObjectType: "WebSocket", MethodName: "onmessage", Description: "WebSocket message data", Assigns: "return"},

	// Next.js sources
	{ID: "js.nextjs.getserversideprops.context", Category: taint.SrcUserInput, Pattern: `context\.(?:query|params|req)\b`, ObjectType: "GetServerSidePropsContext", MethodName: "context", Description: "Next.js getServerSideProps context params/query", Assigns: "return"},
	{ID: "js.nextjs.searchparams", Category: taint.SrcUserInput, Pattern: `\bsearchParams\b`, ObjectType: "PageProps", MethodName: "searchParams", Description: "Next.js App Router searchParams prop", Assigns: "return"},
	{ID: "js.nextjs.api.req.query", Category: taint.SrcUserInput, Pattern: `req\.query`, ObjectType: "NextApiRequest", MethodName: "query", Description: "Next.js API route request query", Assigns: "return"},
	{ID: "js.nextjs.api.req.body", Category: taint.SrcUserInput, Pattern: `req\.body`, ObjectType: "NextApiRequest", MethodName: "body", Description: "Next.js API route request body", Assigns: "return"},

	// Nest.js sources
	{ID: "js.nestjs.query", Category: taint.SrcUserInput, Pattern: `@Query\s*\(`, ObjectType: "NestJS", MethodName: "@Query", Description: "Nest.js @Query() decorator parameter", Assigns: "return"},
	{ID: "js.nestjs.param", Category: taint.SrcUserInput, Pattern: `@Param\s*\(`, ObjectType: "NestJS", MethodName: "@Param", Description: "Nest.js @Param() decorator parameter", Assigns: "return"},
	{ID: "js.nestjs.body", Category: taint.SrcUserInput, Pattern: `@Body\s*\(`, ObjectType: "NestJS", MethodName: "@Body", Description: "Nest.js @Body() decorator parameter", Assigns: "return"},
	{ID: "js.nestjs.headers", Category: taint.SrcUserInput, Pattern: `@Headers\s*\(`, ObjectType: "NestJS", MethodName: "@Headers", Description: "Nest.js @Headers() decorator parameter", Assigns: "return"},

	// Fastify sources
	{ID: "js.fastify.request.params", Category: taint.SrcUserInput, Pattern: `request\.params`, ObjectType: "FastifyRequest", MethodName: "params", Description: "Fastify request route parameters", Assigns: "return"},
	{ID: "js.fastify.request.query", Category: taint.SrcUserInput, Pattern: `request\.query`, ObjectType: "FastifyRequest", MethodName: "query", Description: "Fastify request query string", Assigns: "return"},
	{ID: "js.fastify.request.body", Category: taint.SrcUserInput, Pattern: `request\.body`, ObjectType: "FastifyRequest", MethodName: "body", Description: "Fastify request body", Assigns: "return"},

	// Hapi sources
	{ID: "js.hapi.request.payload", Category: taint.SrcUserInput, Pattern: `request\.payload`, ObjectType: "HapiRequest", MethodName: "payload", Description: "Hapi request payload", Assigns: "return"},
	{ID: "js.hapi.request.params", Category: taint.SrcUserInput, Pattern: `request\.params`, ObjectType: "HapiRequest", MethodName: "params", Description: "Hapi request route parameters", Assigns: "return"},
	{ID: "js.hapi.request.query", Category: taint.SrcUserInput, Pattern: `request\.query`, ObjectType: "HapiRequest", MethodName: "query", Description: "Hapi request query string", Assigns: "return"},

	// GraphQL sources
	{ID: "js.graphql.resolver.args", Category: taint.SrcUserInput, Pattern: `\(\s*(?:parent|root|_)\s*,\s*(?:args|input)\s*[,)]`, ObjectType: "GraphQLResolver", MethodName: "args", Description: "GraphQL resolver args parameter", Assigns: "return"},

	// Socket.io sources
	{ID: "js.socketio.on.data", Category: taint.SrcNetwork, Pattern: `socket\.on\s*\(`, ObjectType: "Socket", MethodName: "on", Description: "Socket.io event data from client", Assigns: "return"},

	// postMessage source
	{ID: "js.postmessage.event.data", Category: taint.SrcExternal, Pattern: `addEventListener\s*\(\s*['"]message['"]`, ObjectType: "window", MethodName: "addEventListener", Description: "postMessage event data (cross-origin)", Assigns: "return"},

	// localStorage/sessionStorage sources
	// Same-origin client-persisted app state: a legitimate second-order source
	// (persisted-XSS) but NOT attacker-supplied request input. Categorised as
	// SrcClientStorage so it emits as a hint but never confers block-eligibility
	// (excluded from genuineExternalSourceCategories, like env_var/cli_arg).
	{ID: "js.localstorage.getitem", Category: taint.SrcClientStorage, Pattern: `localStorage\.getItem\s*\(`, ObjectType: "localStorage", MethodName: "getItem", Description: "localStorage data (potentially tampered)", Assigns: "return"},
	{ID: "js.sessionstorage.getitem", Category: taint.SrcClientStorage, Pattern: `sessionStorage\.getItem\s*\(`, ObjectType: "sessionStorage", MethodName: "getItem", Description: "sessionStorage data (potentially tampered)", Assigns: "return"},

	// AWS Lambda event source
	{ID: "js.aws.lambda.event", Category: taint.SrcExternal, Pattern: `exports\.handler\s*=\s*async\s*\(\s*event|module\.exports\.handler\s*=\s*async\s*\(\s*event`, ObjectType: "aws-lambda", MethodName: "Lambda handler event", Description: "AWS Lambda event data from external trigger", Assigns: "return"},
	// AWS Lambda / API Gateway proxy-integration request fields. The `event`
	// object a Lambda handler receives carries the FULL untrusted HTTP request:
	// `event.body` (raw request body), `event.queryStringParameters`,
	// `event.pathParameters`, `event.headers`, `event.multiValueQueryStringParameters`.
	// Each is attacker-controlled user input (CWE-20) exactly like Express
	// req.body/req.query. The existing handler-declaration source above only marks
	// the parameter at the function boundary; these field-read sources taint at the
	// actual access site so a `const id = event.pathParameters.id` flow is tracked.
	// ObjectType "APIGatewayEvent" is informational (the read is keyed on the
	// `event.<field>` Pattern, which is API-Gateway-specific and does not collide
	// with DOM Event objects — those expose .target/.data, not .pathParameters).
	{ID: "js.aws.apigw.event.fields", Category: taint.SrcUserInput, Pattern: `event\.(?:body|queryStringParameters|multiValueQueryStringParameters|pathParameters|headers|multiValueHeaders|rawQueryString)\b`, ObjectType: "APIGatewayEvent", MethodName: "body/queryStringParameters/multiValueQueryStringParameters/pathParameters/multiValueHeaders/rawQueryString", Description: "AWS Lambda / API Gateway proxy request field (body/query/path/headers) — attacker-controlled HTTP request data (CWE-20)", Assigns: "return"},
	// gRPC server handler — the unary/stream call exposes the client-supplied
	// request message and metadata. `call.request.<field>` is the deserialized
	// request payload (untrusted user input, CWE-20); `call.metadata` carries
	// client-set headers. Anchored to the conventional `call` receiver (the name
	// grpc-node's own docs and generated stubs use for the ServerUnaryCall /
	// ServerWritableStream argument). The Pattern requires the `.request`/`.metadata`
	// sub-access so it does not match an arbitrary `call(...)` invocation.
	{ID: "js.grpc.call.request", Category: taint.SrcUserInput, Pattern: `call\.request\b`, ObjectType: "ServerUnaryCall", MethodName: "request", Description: "gRPC server handler call.request — client-supplied request message (untrusted user input, CWE-20)", Assigns: "return"},
	{ID: "js.grpc.call.metadata", Category: taint.SrcUserInput, Pattern: `call\.metadata\b`, ObjectType: "ServerUnaryCall", MethodName: "metadata", Description: "gRPC server handler call.metadata — client-set request metadata/headers (untrusted, CWE-20)", Assigns: "return"},
	// AWS SQS message source
	{ID: "js.aws.sqs.receive", Category: taint.SrcExternal, Pattern: `\.receiveMessage\s*\(`, ObjectType: "SQS", MethodName: "receiveMessage", Description: "AWS SQS message data from queue", Assigns: "return"},
	// AWS S3 object source
	{ID: "js.aws.s3.getobject", Category: taint.SrcExternal, Pattern: `\.getObject\s*\(`, ObjectType: "S3", MethodName: "getObject", Description: "AWS S3 object data from potentially untrusted bucket", Assigns: "return"},
	// GCP Cloud Functions event source
	{ID: "js.gcp.cloudfunctions.event", Category: taint.SrcExternal, Pattern: `exports\.\w+\s*=\s*(?:async\s*)?\(\s*(?:req|event|message)\s*,\s*(?:res|context)\s*\)`, ObjectType: "cloud.google.com/functions", MethodName: "Cloud Function handler", Description: "GCP Cloud Functions event data from external trigger", Assigns: "return"},
	// GCP Pub/Sub pull
	{ID: "js.gcp.pubsub.pull", Category: taint.SrcExternal, Pattern: `subscription\.on\s*\(\s*['"]message['"]`, ObjectType: "PubSub", MethodName: "subscription.on(message)", Description: "GCP Pub/Sub message data via subscription", Assigns: "return"},

	// Koa.js sources
	{ID: "js.koa.ctx.query", Category: taint.SrcUserInput, Pattern: `ctx\.query`, ObjectType: "KoaContext", MethodName: "query", Description: "Koa.js context query parameters", Assigns: "return"},
	{ID: "js.koa.ctx.request.body", Category: taint.SrcUserInput, Pattern: `ctx\.request\.body`, ObjectType: "KoaContext", MethodName: "request.body", Description: "Koa.js context request body", Assigns: "return"},
	{ID: "js.koa.ctx.params", Category: taint.SrcUserInput, Pattern: `ctx\.params`, ObjectType: "KoaContext", MethodName: "params", Description: "Koa.js context route parameters", Assigns: "return"},

	// Express additional sources
	{ID: "js.express.req.get", Category: taint.SrcUserInput, Pattern: `req\.get\s*\(`, ObjectType: "Request", MethodName: "get", Description: "Express req.get() header accessor", Assigns: "return"},
	{ID: "js.express.req.ip", Category: taint.SrcUserInput, Pattern: `req\.ip\b|req\.ips\b`, ObjectType: "Request", MethodName: "ip/ips", Description: "Express client IP address (spoofable via X-Forwarded-For)", Assigns: "return"},
	{ID: "js.express.req.hostname", Category: taint.SrcUserInput, Pattern: `req\.hostname`, ObjectType: "Request", MethodName: "hostname", Description: "Express request hostname (spoofable via Host header)", Assigns: "return"},

	// FormData API
	{ID: "js.formdata.get", Category: taint.SrcUserInput, Pattern: `formData\.get\s*\(|formData\.getAll\s*\(`, ObjectType: "FormData", MethodName: "get/getAll", Description: "FormData API value retrieval", Assigns: "return"},

	// Koa.js additional sources
	{ID: "js.koa.ctx.headers", Category: taint.SrcUserInput, Pattern: `ctx\.headers`, ObjectType: "KoaContext", MethodName: "headers", Description: "Koa.js context request headers", Assigns: "return"},
	{ID: "js.koa.ctx.cookies.get", Category: taint.SrcUserInput, Pattern: `ctx\.cookies\.get\s*\(`, ObjectType: "KoaContext", MethodName: "cookies.get", Description: "Koa.js cookie value retrieval", Assigns: "return"},
	{ID: "js.koa.ctx.request.query", Category: taint.SrcUserInput, Pattern: `ctx\.request\.query`, ObjectType: "KoaContext", MethodName: "request.query", Description: "Koa.js request query parameters object", Assigns: "return"},

	// Fastify additional sources
	{ID: "js.fastify.request.headers", Category: taint.SrcUserInput, Pattern: `request\.headers`, ObjectType: "FastifyRequest", MethodName: "headers", Description: "Fastify request headers", Assigns: "return"},
	{ID: "js.fastify.request.raw", Category: taint.SrcUserInput, Pattern: `request\.raw`, ObjectType: "FastifyRequest", MethodName: "raw", Description: "Fastify raw Node.js IncomingMessage", Assigns: "return"},

	// Hono sources
	{ID: "js.hono.req.query", Category: taint.SrcUserInput, Pattern: `c\.req\.query\s*\(`, ObjectType: "HonoContext", MethodName: "req.query", Description: "Hono query parameter", Assigns: "return"},
	{ID: "js.hono.req.param", Category: taint.SrcUserInput, Pattern: `c\.req\.param\s*\(`, ObjectType: "HonoContext", MethodName: "req.param", Description: "Hono route parameter", Assigns: "return"},
	{ID: "js.hono.req.json", Category: taint.SrcUserInput, Pattern: `c\.req\.json\s*\(`, ObjectType: "HonoContext", MethodName: "req.json", Description: "Hono JSON request body", Assigns: "return"},
	{ID: "js.hono.req.header", Category: taint.SrcUserInput, Pattern: `c\.req\.header\s*\(`, ObjectType: "HonoContext", MethodName: "req.header", Description: "Hono request header value", Assigns: "return"},
	{ID: "js.hono.req.text", Category: taint.SrcUserInput, Pattern: `c\.req\.text\s*\(`, ObjectType: "HonoContext", MethodName: "req.text", Description: "Hono raw body text", Assigns: "return"},
	{ID: "js.hono.req.raw", Category: taint.SrcUserInput, Pattern: `c\.req\.raw`, ObjectType: "HonoContext", MethodName: "req.raw", Description: "Hono raw Request object", Assigns: "return"},

	// Remix sources
	{ID: "js.remix.request.formdata", Category: taint.SrcUserInput, Pattern: `request\.formData\s*\(`, ObjectType: "Request", MethodName: "formData", Description: "Remix form submission data", Assigns: "return"},
	{ID: "js.remix.request.json", Category: taint.SrcUserInput, Pattern: `request\.json\s*\(`, ObjectType: "Request", MethodName: "json", Description: "Remix JSON request body", Assigns: "return"},
	{ID: "js.remix.url.searchparams", Category: taint.SrcUserInput, Pattern: `new\s+URL\s*\(\s*request\.url\s*\)\.searchParams`, ObjectType: "URL", MethodName: "searchParams", Description: "Remix URL search parameters", Assigns: "return"},

	// Astro sources
	{ID: "js.astro.url.searchparams", Category: taint.SrcUserInput, Pattern: `Astro\.url\.searchParams`, ObjectType: "Astro", MethodName: "url.searchParams", Description: "Astro query parameters", Assigns: "return"},
	{ID: "js.astro.request", Category: taint.SrcUserInput, Pattern: `Astro\.request`, ObjectType: "Astro", MethodName: "request", Description: "Astro request object", Assigns: "return"},

	// Socket.IO additional sources
	{ID: "js.socketio.handshake", Category: taint.SrcNetwork, Pattern: `socket\.handshake\.query`, ObjectType: "Socket", MethodName: "handshake.query", Description: "Socket.IO handshake query parameters", Assigns: "return"},

	// GraphQL additional sources
	{ID: "js.graphql.context", Category: taint.SrcUserInput, Pattern: `context\.req\b|context\.request\b`, ObjectType: "GraphQLContext", MethodName: "context.req", Description: "GraphQL context with underlying HTTP request", Assigns: "return"},

	// Hapi additional sources
	{ID: "js.hapi.request.headers", Category: taint.SrcUserInput, Pattern: `request\.headers`, ObjectType: "HapiRequest", MethodName: "headers", Description: "Hapi request headers", Assigns: "return"},
	{ID: "js.hapi.request.state", Category: taint.SrcUserInput, Pattern: `request\.state`, ObjectType: "HapiRequest", MethodName: "state", Description: "Hapi request cookies/state", Assigns: "return"},

	// readline input
	{ID: "js.readline.input", Category: taint.SrcUserInput, Pattern: `readline\.question\s*\(|rl\.question\s*\(`, ObjectType: "readline", MethodName: "question", Description: "readline user input from terminal", Assigns: "return"},

	// WebSocket message data
	{ID: "js.websocket.message.data", Category: taint.SrcNetwork, Pattern: `ws\.on\s*\(\s*['"]message['"]`, ObjectType: "WebSocket", MethodName: "on(message)", Description: "WebSocket message data from client", Assigns: "return"},

	// Next.js additional sources
	{ID: "js.nextjs.useSearchParams", Category: taint.SrcUserInput, Pattern: `useSearchParams\s*\(`, ObjectType: "NextJS", MethodName: "useSearchParams", Description: "Next.js App Router useSearchParams hook", Assigns: "return"},
	{ID: "js.nextjs.useParams", Category: taint.SrcUserInput, Pattern: `useParams\s*\(`, ObjectType: "NextJS", MethodName: "useParams", Description: "Next.js App Router useParams hook", Assigns: "return"},

	// Express req.file (multer)
	{ID: "js.express.req.file", Category: taint.SrcUserInput, Pattern: `req\.file\b|req\.files\b`, ObjectType: "Request", MethodName: "file/files", Description: "Express file upload via multer middleware", Assigns: "return"},

	// IP-based trust bypass sources
	{ID: "js.express.req.headers.xforwardedfor", Category: taint.SrcUserInput, Pattern: `req\.headers\s*\[\s*['"]x-forwarded-for['"]\s*\]`, ObjectType: "Request", MethodName: "headers['x-forwarded-for']", Description: "X-Forwarded-For header (client-controlled, IP spoofing)", Assigns: "return"},
	{ID: "js.express.req.socket.remoteaddress", Category: taint.SrcUserInput, Pattern: `req\.socket\.remoteAddress|req\.connection\.remoteAddress`, ObjectType: "Request", MethodName: "socket.remoteAddress", Description: "Client IP address from socket (spoofable via proxy)", Assigns: "return"},

	// SvelteKit sources
	{ID: "js.sveltekit.event.url.searchparams", Category: taint.SrcUserInput, Pattern: `event\.url\.searchParams\.get\s*\(`, ObjectType: "RequestEvent", MethodName: "event.url.searchParams.get", Description: "SvelteKit URL search parameter in load/actions", Assigns: "return"},
	{ID: "js.sveltekit.event.request.formdata", Category: taint.SrcUserInput, Pattern: `event\.request\.formData\s*\(`, ObjectType: "RequestEvent", MethodName: "event.request.formData", Description: "SvelteKit form submission data in actions", Assigns: "return"},
	{ID: "js.sveltekit.event.params", Category: taint.SrcUserInput, Pattern: `event\.params`, ObjectType: "RequestEvent", MethodName: "event.params", Description: "SvelteKit route parameters", Assigns: "return"},
	{ID: "js.sveltekit.event.cookies.get", Category: taint.SrcUserInput, Pattern: `event\.cookies\.get\s*\(`, ObjectType: "RequestEvent", MethodName: "event.cookies.get", Description: "SvelteKit cookie value", Assigns: "return"},

	// Next.js App Router sources
	{ID: "js.nextjs.approuter.searchparams", Category: taint.SrcUserInput, Pattern: `searchParams\s*[\[.]`, ObjectType: "PageProps", MethodName: "searchParams", Description: "Next.js App Router searchParams page prop", Assigns: "return"},
	{ID: "js.nextjs.approuter.params", Category: taint.SrcUserInput, Pattern: `params\.\w+`, ObjectType: "PageProps", MethodName: "params", Description: "Next.js App Router dynamic route params", Assigns: "return"},
	{ID: "js.nextjs.cookies", Category: taint.SrcUserInput, Pattern: `cookies\s*\(\s*\)`, ObjectType: "next/headers", MethodName: "cookies", Description: "Next.js App Router cookies() from next/headers", Assigns: "return"},
	{ID: "js.nextjs.headers", Category: taint.SrcUserInput, Pattern: `headers\s*\(\s*\)`, ObjectType: "next/headers", MethodName: "headers", Description: "Next.js App Router headers() from next/headers", Assigns: "return"},
	{ID: "js.nextjs.nextrequest.nexturl.searchparams", Category: taint.SrcUserInput, Pattern: `NextRequest\.nextUrl\.searchParams|request\.nextUrl\.searchParams|req\.nextUrl\.searchParams`, ObjectType: "NextRequest", MethodName: "nextUrl.searchParams", Description: "Next.js NextRequest URL search parameters", Assigns: "return"},

	// H3/Nitro sources (powers Nuxt server-side, standalone H3 apps)
	{ID: "js.h3.getquery", Category: taint.SrcUserInput, Pattern: `getQuery\s*\(`, ObjectType: "", MethodName: "getQuery", Description: "H3/Nitro query parameters via getQuery(event)", Assigns: "return"},
	{ID: "js.h3.readbody", Category: taint.SrcUserInput, Pattern: `readBody\s*\(`, ObjectType: "", MethodName: "readBody", Description: "H3/Nitro request body via readBody(event)", Assigns: "return"},
	{ID: "js.h3.getrouterparam", Category: taint.SrcUserInput, Pattern: `getRouterParam\s*\(`, ObjectType: "", MethodName: "getRouterParam", Description: "H3/Nitro single route parameter via getRouterParam(event, name)", Assigns: "return"},
	{ID: "js.h3.getrouterparams", Category: taint.SrcUserInput, Pattern: `getRouterParams\s*\(`, ObjectType: "", MethodName: "getRouterParams", Description: "H3/Nitro all route parameters via getRouterParams(event)", Assigns: "return"},
	{ID: "js.h3.readformdata", Category: taint.SrcUserInput, Pattern: `readFormData\s*\(`, ObjectType: "", MethodName: "readFormData", Description: "H3/Nitro form data via readFormData(event)", Assigns: "return"},
	{ID: "js.h3.getrequestheaders", Category: taint.SrcUserInput, Pattern: `getRequestHeaders\s*\(|getRequestHeader\s*\(`, ObjectType: "", MethodName: "getRequestHeaders", Description: "H3/Nitro request headers via getRequestHeaders(event)", Assigns: "return"},

	// AdonisJS sources
	{ID: "js.adonis.request.all", Category: taint.SrcUserInput, Pattern: `request\.all\s*\(\s*\)`, ObjectType: "AdonisRequest", MethodName: "all", Description: "AdonisJS request.all() — merged body + query string", Assigns: "return"},
	{ID: "js.adonis.request.input", Category: taint.SrcUserInput, Pattern: `request\.input\s*\(`, ObjectType: "AdonisRequest", MethodName: "input", Description: "AdonisJS request.input(key) — single request field", Assigns: "return"},
	{ID: "js.adonis.request.only", Category: taint.SrcUserInput, Pattern: `request\.only\s*\(\s*\[`, ObjectType: "AdonisRequest", MethodName: "only", Description: "AdonisJS request.only([keys]) — cherry-picked request fields", Assigns: "return"},
	{ID: "js.adonis.request.qs", Category: taint.SrcUserInput, Pattern: `request\.qs\s*\(\s*\)`, ObjectType: "AdonisRequest", MethodName: "qs", Description: "AdonisJS request.qs() — query string parameters", Assigns: "return"},
	{ID: "js.adonis.request.param", Language: rules.LangJavaScript, Category: taint.SrcUserInput, Pattern: `request\.param\s*\(`, ObjectType: "AdonisRequest", MethodName: "param", Description: "AdonisJS request.param(key) — single route parameter", Assigns: "return"},
	{ID: "js.adonis.request.params", Language: rules.LangJavaScript, Category: taint.SrcUserInput, Pattern: `request\.params\s*\(\s*\)`, ObjectType: "AdonisRequest", MethodName: "params", Description: "AdonisJS request.params() — all route parameters", Assigns: "return"},
	{ID: "js.adonis.request.except", Language: rules.LangJavaScript, Category: taint.SrcUserInput, Pattern: `request\.except\s*\(\s*\[`, ObjectType: "AdonisRequest", MethodName: "except", Description: "AdonisJS request.except([keys]) — request fields minus the excluded ones", Assigns: "return"},
	{ID: "js.adonis.request.cookie", Language: rules.LangJavaScript, Category: taint.SrcUserInput, Pattern: `request\.(?:plainCookie|cookie)\s*\(`, ObjectType: "AdonisRequest", MethodName: "cookie/plainCookie", Description: "AdonisJS request.cookie(key) / request.plainCookie(key) — request cookie value", Assigns: "return"},
	{ID: "js.adonis.request.header", Language: rules.LangJavaScript, Category: taint.SrcUserInput, Pattern: `request\.header\s*\(`, ObjectType: "AdonisRequest", MethodName: "header", Description: "AdonisJS request.header(key) — request header value", Assigns: "return"},

	// --- Database result sources (second-order injection) ---
	// Data read from databases may contain attacker-controlled values stored earlier.
	// These sources enable detection of second-order XSS, SQL injection, and other
	// vulnerabilities where tainted data passes through a database before reaching a sink.

	// MongoDB / Mongoose
	{ID: "js.mongodb.findone", Category: taint.SrcDatabase, Pattern: `\.findOne\s*\(`, ObjectType: "", MethodName: "findOne", Description: "MongoDB/Mongoose findOne() result may contain attacker-stored data", Assigns: "return"},
	{ID: "js.mongoose.findbyid", Category: taint.SrcDatabase, Pattern: `\.findById\s*\(`, ObjectType: "", MethodName: "findById", Description: "Mongoose findById() result may contain attacker-stored data", Assigns: "return"},
	{ID: "js.mongodb.aggregate", Category: taint.SrcDatabase, Pattern: `\.aggregate\s*\(\s*\[`, ObjectType: "", MethodName: "aggregate", Description: "MongoDB aggregate() pipeline results may contain attacker-stored data", Assigns: "return"},
	{ID: "js.mongodb.distinct", Category: taint.SrcDatabase, Pattern: `\.distinct\s*\(`, ObjectType: "", MethodName: "distinct", Description: "MongoDB distinct() results may contain attacker-stored data", Assigns: "return"},
	// Compound find-and-modify read-back operations return the document as it
	// existed *before* the modification (driver default returnDocument:'before'),
	// so any attacker-stored field in that document flows back to the caller — a
	// second-order taint source mirroring php.mongodb.findoneandupdate (PR #1203)
	// and rust MongoDB find_one_and_* (PR #1126). Method names are MongoDB/Mongoose-
	// unique, so an empty ObjectType is FP-safe.
	{ID: "js.mongodb.findoneandupdate", Category: taint.SrcDatabase, Pattern: `\.findOneAndUpdate\s*\(`, ObjectType: "", MethodName: "findOneAndUpdate", Description: "MongoDB/Mongoose findOneAndUpdate() returns the pre-update document, which may contain attacker-stored data", Assigns: "return"},
	{ID: "js.mongodb.findoneandreplace", Category: taint.SrcDatabase, Pattern: `\.findOneAndReplace\s*\(`, ObjectType: "", MethodName: "findOneAndReplace", Description: "MongoDB/Mongoose findOneAndReplace() returns the pre-replacement document, which may contain attacker-stored data", Assigns: "return"},
	{ID: "js.mongodb.findoneanddelete", Category: taint.SrcDatabase, Pattern: `\.findOneAndDelete\s*\(`, ObjectType: "", MethodName: "findOneAndDelete", Description: "MongoDB/Mongoose findOneAndDelete() returns the deleted document, which may contain attacker-stored data", Assigns: "return"},
	{ID: "js.mongoose.findbyidandupdate", Category: taint.SrcDatabase, Pattern: `\.findByIdAndUpdate\s*\(`, ObjectType: "", MethodName: "findByIdAndUpdate", Description: "Mongoose findByIdAndUpdate() returns the pre-update document, which may contain attacker-stored data", Assigns: "return"},
	{ID: "js.mongoose.findbyidanddelete", Category: taint.SrcDatabase, Pattern: `\.findByIdAndDelete\s*\(`, ObjectType: "", MethodName: "findByIdAndDelete", Description: "Mongoose findByIdAndDelete() returns the deleted document, which may contain attacker-stored data", Assigns: "return"},

	// Sequelize ORM
	// Tightened 2026-04-25: previous `\.findAll\s*\(` matched every
	// `.findAll(` call — Vue Test Utils `wrapper.findAll('.selector')`,
	// custom helpers, jQuery-like utilities — producing 14 NoSQL-
	// injection FPs in owncloud/web .spec.ts files (Vue Test Utils
	// `findAll().find()` chains). Sequelize `findAll` is invoked with
	// no args or an options object literal `{where: ...}`. Require one
	// of those shapes — string/predicate arguments are not Sequelize.
	{ID: "js.sequelize.findall", Category: taint.SrcDatabase, Pattern: `\.findAll\s*\(\s*(?:\{|\))`, ObjectType: "", MethodName: "findAll", Description: "Sequelize findAll() results may contain attacker-stored data", Assigns: "return"},
	{ID: "js.sequelize.findbypk", Category: taint.SrcDatabase, Pattern: `\.findByPk\s*\(`, ObjectType: "", MethodName: "findByPk", Description: "Sequelize findByPk() result may contain attacker-stored data", Assigns: "return"},
	{ID: "js.sequelize.findandcountall", Category: taint.SrcDatabase, Pattern: `\.findAndCountAll\s*\(`, ObjectType: "", MethodName: "findAndCountAll", Description: "Sequelize findAndCountAll() results may contain attacker-stored data", Assigns: "return"},

	// Prisma ORM (second-order taint via canonical findX() read methods).
	// Method names are distinctive — only Prisma's client uses findUnique /
	// findFirst / findMany / findUniqueOrThrow / findFirstOrThrow as its
	// canonical read API (TypeORM/Mongoose/Sequelize use different names).
	{ID: "js.prisma.findunique", Category: taint.SrcDatabase, Pattern: `\.findUnique\s*\(`, ObjectType: "", MethodName: "findUnique", Description: "Prisma findUnique() result may contain attacker-stored data", Assigns: "return"},
	{ID: "js.prisma.finduniqueorthrow", Category: taint.SrcDatabase, Pattern: `\.findUniqueOrThrow\s*\(`, ObjectType: "", MethodName: "findUniqueOrThrow", Description: "Prisma findUniqueOrThrow() result may contain attacker-stored data", Assigns: "return"},
	{ID: "js.prisma.findfirst", Category: taint.SrcDatabase, Pattern: `\.findFirst\s*\(`, ObjectType: "", MethodName: "findFirst", Description: "Prisma findFirst() result may contain attacker-stored data", Assigns: "return"},
	{ID: "js.prisma.findfirstorthrow", Category: taint.SrcDatabase, Pattern: `\.findFirstOrThrow\s*\(`, ObjectType: "", MethodName: "findFirstOrThrow", Description: "Prisma findFirstOrThrow() result may contain attacker-stored data", Assigns: "return"},
	{ID: "js.prisma.findmany", Category: taint.SrcDatabase, Pattern: `\.findMany\s*\(`, ObjectType: "", MethodName: "findMany", Description: "Prisma findMany() results may contain attacker-stored data", Assigns: "return"},

	// PostgreSQL (pg) / MySQL (mysql2)
	{ID: "js.pg.pool.query", Category: taint.SrcDatabase, Pattern: `pool\.query\s*\(`, ObjectType: "pool", MethodName: "query", Description: "PostgreSQL pool.query() results may contain attacker-stored data", Assigns: "return"},
	{ID: "js.mysql.connection.query", Category: taint.SrcDatabase, Pattern: `connection\.query\s*\(`, ObjectType: "connection", MethodName: "query", Description: "MySQL connection.query() results may contain attacker-stored data", Assigns: "return"},
	{ID: "js.knex.raw", Category: taint.SrcDatabase, Pattern: `knex\.raw\s*\(`, ObjectType: "knex", MethodName: "raw", Description: "Knex raw() query results may contain attacker-stored data", Assigns: "return"},

	// Web Fetch API Request body methods (Bun.serve, Deno.serve, Cloudflare Workers)
	{ID: "js.webapi.req.json", Category: taint.SrcUserInput, Pattern: `(?:req|request)\.json\s*\(`, ObjectType: "Request", MethodName: "json", Description: "Web API Request.json() body parsing (Bun/Deno/Workers)", Assigns: "return"},
	{ID: "js.webapi.req.text", Category: taint.SrcUserInput, Pattern: `(?:req|request)\.text\s*\(`, ObjectType: "Request", MethodName: "text", Description: "Web API Request.text() body parsing (Bun/Deno/Workers)", Assigns: "return"},
	{ID: "js.webapi.req.formdata", Category: taint.SrcUserInput, Pattern: `(?:req|request)\.formData\s*\(`, ObjectType: "Request", MethodName: "formData", Description: "Web API Request.formData() body parsing (Bun/Deno/Workers)", Assigns: "return"},

	// --- Cloudflare Workers — KV/R2 read sources (second-order taint) ---
	// User input written to KV/R2 on one request and read back on a later
	// request flows through the data layer; without these sources the
	// downstream sink (eval, fetch, exec, html) would not fire on the
	// stored-then-read path. Same pattern as the redis-py / Jedis / go-redis
	// second-order cycles.
	//
	// Placed BEFORE the Deno-specific block so the matcher iterates these
	// candidates first for MethodName="get": the matcher's qualified-receiver
	// component loop otherwise lets ObjectType="Deno.env" (lastPart "env")
	// match any `env.<X>.get(...)` receiver because `env` appears as an
	// intermediate path component. CF binding names (env.KV, env.R2) are
	// canonical for Workers projects (https://developers.cloudflare.com/...).
	//
	// Refs:
	//   https://developers.cloudflare.com/kv/api/read-key-value-pairs/
	//   https://developers.cloudflare.com/r2/api/workers/workers-api-reference/#bucket-method-definitions
	{ID: "js.cloudflare.kv.get", Category: taint.SrcExternal, Pattern: `\.get\s*\(`, ObjectType: "KVNamespace", MethodName: "get", Description: "Cloudflare Workers KVNamespace.get(key) returns previously-stored value — attacker-controlled if an earlier .put() wrote user input (second-order taint)", Assigns: "return"},
	{ID: "js.cloudflare.kv.getwithmetadata", Category: taint.SrcExternal, Pattern: `\.getWithMetadata\s*\(`, ObjectType: "KVNamespace", MethodName: "getWithMetadata", Description: "Cloudflare Workers KVNamespace.getWithMetadata(key) — same second-order taint as .get() plus stored metadata (also attacker-controlled if any earlier .put() wrote user input)", Assigns: "return"},
	{ID: "js.cloudflare.r2.get", Category: taint.SrcExternal, Pattern: `\.get\s*\(`, ObjectType: "R2Bucket", MethodName: "get", Description: "Cloudflare Workers R2Bucket.get(key) returns the stored object body — attacker-controlled if any earlier .put() wrote a user-uploaded payload (second-order taint)", Assigns: "return"},

	// Deno-specific sources
	{ID: "js.deno.env.get", Category: taint.SrcEnvVar, Pattern: `Deno\.env\.get\s*\(`, ObjectType: "Deno.env", MethodName: "get", Description: "Deno environment variable access", Assigns: "return"},
	{ID: "js.deno.args", Category: taint.SrcCLIArg, Pattern: `Deno\.args`, ObjectType: "Deno", MethodName: "args", Description: "Deno command-line arguments", Assigns: "return"},
	{ID: "js.deno.stdin", Category: taint.SrcUserInput, Pattern: `Deno\.stdin\b`, ObjectType: "Deno", MethodName: "stdin", Description: "Deno stdin readable stream — user input via terminal/pipe", Assigns: "return"},
	{ID: "js.deno.env.toobject", Category: taint.SrcEnvVar, Pattern: `Deno\.env\.toObject\s*\(`, ObjectType: "Deno.env", MethodName: "toObject", Description: "Deno environment variable map (all env vars)", Assigns: "return"},
	{ID: "js.deno.readtextfile.result", Category: taint.SrcFileRead, Pattern: `Deno\.readTextFile\s*\(`, ObjectType: "Deno", MethodName: "readTextFile", Description: "Deno.readTextFile() returns untrusted file content as string", Assigns: "return"},
	{ID: "js.deno.readtextfilesync.result", Category: taint.SrcFileRead, Pattern: `Deno\.readTextFileSync\s*\(`, ObjectType: "Deno", MethodName: "readTextFileSync", Description: "Deno.readTextFileSync() returns untrusted file content as string", Assigns: "return"},
	{ID: "js.deno.readfile.result", Category: taint.SrcFileRead, Pattern: `Deno\.readFile\s*\(`, ObjectType: "Deno", MethodName: "readFile", Description: "Deno.readFile() returns untrusted file content as Uint8Array", Assigns: "return"},
	{ID: "js.deno.command.result", Category: taint.SrcUserInput, Pattern: `new\s+Deno\.Command\s*\(`, ObjectType: "Deno", MethodName: "Command", Description: "Deno.Command instance encapsulates untrusted subprocess output (.output(), .stderrOutput())", Assigns: "return"},
	{ID: "js.deno.run.result", Category: taint.SrcUserInput, Pattern: `Deno\.run\s*\(`, ObjectType: "Deno", MethodName: "run", Description: "Deno.run() (legacy) returns Process whose .output() yields untrusted subprocess bytes", Assigns: "return"},

	// Bun-specific runtime sources (https://bun.sh/docs/api). Bun.serve handlers
	// receive a Web API Request (covered by js.webapi.req.*); these entries cover
	// the Bun-specific runtime APIs not exposed via the Web API surface.
	{ID: "js.bun.argv", Category: taint.SrcCLIArg, Pattern: `Bun\.argv\b`, ObjectType: "Bun", MethodName: "argv", Description: "Bun.argv command-line arguments (Bun runtime equivalent of process.argv)", Assigns: "return"},
	{ID: "js.bun.env", Category: taint.SrcEnvVar, Pattern: `Bun\.env\b`, ObjectType: "Bun", MethodName: "env", Description: "Bun.env environment variables (Bun runtime equivalent of process.env)", Assigns: "return"},
	{ID: "js.bun.stdin", Category: taint.SrcUserInput, Pattern: `Bun\.stdin\b`, ObjectType: "Bun", MethodName: "stdin", Description: "Bun.stdin readable stream — user input via terminal/pipe", Assigns: "return"},
	{ID: "js.bun.spawn.result", Category: taint.SrcUserInput, Pattern: `Bun\.spawn\s*\(`, ObjectType: "Bun", MethodName: "spawn", Description: "Bun.spawn() returns Subprocess whose .stdout/.stderr yield untrusted process output", Assigns: "return"},
	{ID: "js.bun.spawnsync.result", Category: taint.SrcUserInput, Pattern: `Bun\.spawnSync\s*\(`, ObjectType: "Bun", MethodName: "spawnSync", Description: "Bun.spawnSync() returns SyncSubprocess whose .stdout/.stderr yield untrusted process output", Assigns: "return"},

	// Deserialized data sources (binary/structured formats)
	{ID: "js.msgpack.decode", Category: taint.SrcDeserialized, Pattern: `msgpack\.decode\s*\(`, ObjectType: "msgpack", MethodName: "decode", Description: "MessagePack decoded data (@msgpack/msgpack) — untrusted binary yields arbitrary structures", Assigns: "return"},
	{ID: "js.msgpack.unpack", Category: taint.SrcDeserialized, Pattern: `msgpack\.unpack\s*\(`, ObjectType: "msgpack", MethodName: "unpack", Description: "MessagePack unpacked data (msgpack-lite) — untrusted binary yields arbitrary structures", Assigns: "return"},
	{ID: "js.bson.deserialize", Category: taint.SrcDeserialized, Pattern: `BSON\.deserialize\s*\(`, ObjectType: "BSON", MethodName: "deserialize", Description: "BSON deserialized data (mongodb/bson) — untrusted wire-format yields arbitrary objects", Assigns: "return"},
	{ID: "js.bson.deserializestream", Category: taint.SrcDeserialized, Pattern: `BSON\.deserializeStream\s*\(`, ObjectType: "BSON", MethodName: "deserializeStream", Description: "BSON stream deserialization — multiple documents from untrusted binary stream", Assigns: "return"},
	{ID: "js.cbor.decode", Category: taint.SrcDeserialized, Pattern: `cbor\.decode\s*\(`, ObjectType: "cbor", MethodName: "decode", Description: "CBOR decoded data (cbor/cbor-x) — untrusted binary yields arbitrary nested structures", Assigns: "return"},
	{ID: "js.cbor.decodemultiple", Category: taint.SrcDeserialized, Pattern: `cbor\.decodeMultiple\s*\(`, ObjectType: "cbor", MethodName: "decodeMultiple", Description: "CBOR multiple-value decode (cbor-x) — sequential values from untrusted binary", Assigns: "return"},

	// --- Electron IPC sources (renderer → main process) ---
	// Data sent from the renderer process via IPC is user-controlled when the renderer
	// loads web content. Attackers can exploit XSS in the renderer to send arbitrary
	// IPC messages to the main process, which has full Node.js access.
	{ID: "js.electron.ipcmain.on", Category: taint.SrcUserInput, Pattern: `ipcMain\.on\s*\(`, ObjectType: "electron.ipcMain", MethodName: "on", Description: "Electron IPC message from renderer — user-controlled if renderer loads web content", Assigns: "return"},
	{ID: "js.electron.ipcmain.handle", Category: taint.SrcUserInput, Pattern: `ipcMain\.handle\s*\(`, ObjectType: "electron.ipcMain", MethodName: "handle", Description: "Electron IPC handle from renderer — async handler receiving user-controlled data", Assigns: "return"},

	// --- Electron deep link / custom protocol sources ---
	// External applications and web pages can send URLs to the Electron app via
	// custom protocol handlers (e.g., myapp://payload). These are fully attacker-controlled.
	{ID: "js.electron.app.openurl", Category: taint.SrcExternal, Pattern: `app\.on\s*\(\s*['"]open-url['"]`, ObjectType: "electron.app", MethodName: "on('open-url')", Description: "Electron deep link URL from external app/browser — fully attacker-controlled (CVE-2022-36077)", Assigns: "return"},
	{ID: "js.electron.app.secondinstance", Category: taint.SrcExternal, Pattern: `app\.on\s*\(\s*['"]second-instance['"]`, ObjectType: "electron.app", MethodName: "on('second-instance')", Description: "Electron second-instance event — command-line args from protocol handler invocation", Assigns: "return"},
	{ID: "js.electron.protocol.handle", Category: taint.SrcExternal, Pattern: `protocol\.handle\s*\(`, ObjectType: "electron.protocol", MethodName: "handle", Description: "Electron custom protocol handler — request URL/body from external sources", Assigns: "return"},

	// --- Archive entry name sources (Zip Slip / Tar Slip — CWE-22) ---
	// Archive entries' pathname fields are read from the archive header and are
	// fully attacker-controlled (e.g., "../../etc/passwd" or absolute paths).
	// When these flow into path.join/fs.writeFile/fs.createWriteStream without
	// basename/normalize/containment validation, the attacker writes outside
	// the extraction root (Snyk Zip Slip 2018; CVE-2018-1002204 adm-zip;
	// CVE-2021-32803, CVE-2021-37701 node-tar; CVE-2022-48285 jszip).
	{ID: "js.admzip.entry.entryname", Category: taint.SrcExternal, Pattern: `\.entryName\b`, ObjectType: "adm-zip.Entry", MethodName: "entryName", Description: "adm-zip IZipEntry.entryName — raw archive entry path (Zip Slip, CVE-2018-1002204)", Assigns: "return"},
	{ID: "js.yauzl.entry.filename", Category: taint.SrcExternal, Pattern: `\.fileName\b`, ObjectType: "yauzl.Entry", MethodName: "fileName", Description: "yauzl Entry.fileName — raw archive entry path from untrusted zip (Zip Slip)", Assigns: "return"},

	// --- Redis read sources (node-redis v4 / ioredis) — second-order taint ---
	// User input written to Redis on one request and read back by a later request
	// flows through the data layer; tsflow needs these as SrcExternal so the
	// downstream sink (XSS, SQLi, command/Lua injection) is caught. The existing
	// js.redis.sendcommand / js.redis.eval sinks already handle the write side.
	// MethodName packs node-redis v4 camelCase + ioredis/node-redis-v3 lowercase
	// variants so tsflow registers both. Mirrors java.jedis.* (PR #641),
	// go.redis.* (PR #647), python redis-py reads (PR #685), csharp.redis.* and
	// the multi-language Redis-source addition cycle. ObjectType "RedisClient"
	// matches the existing js.redis.* sink entries; the regex-fallback Pattern is
	// deliberately scoped to the `redis` / `redisClient` receiver names only
	// (generic names like `client` / `cache` are NOT in the allowlist) and to
	// Redis-specific command method names (no bare `get`), to avoid matching
	// non-Redis HTTP clients or ORM/query-builder cursors.
	{ID: "js.redis.hget", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:hGet|hget)\s*\(`, ObjectType: "RedisClient", MethodName: "hGet/hget", Description: "Redis HGET — hash field value (possibly user-controlled cached data)", Assigns: "return"},
	{ID: "js.redis.hgetall", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:hGetAll|hgetall)\s*\(`, ObjectType: "RedisClient", MethodName: "hGetAll/hgetall", Description: "Redis HGETALL — all hash fields/values (possibly user-controlled cached data)", Assigns: "return"},
	{ID: "js.redis.hkeys", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:hKeys|hkeys)\s*\(`, ObjectType: "RedisClient", MethodName: "hKeys/hkeys", Description: "Redis HKEYS — hash field names (possibly user-controlled cached data)", Assigns: "return"},
	{ID: "js.redis.hvals", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:hVals|hvals)\s*\(`, ObjectType: "RedisClient", MethodName: "hVals/hvals", Description: "Redis HVALS — hash values (possibly user-controlled cached data)", Assigns: "return"},
	{ID: "js.redis.hmget", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:hmGet|hMGet|hmget)\s*\(`, ObjectType: "RedisClient", MethodName: "hmGet/hMGet/hmget", Description: "Redis HMGET — multiple hash field values (possibly user-controlled cached data)", Assigns: "return"},
	{ID: "js.redis.mget", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:mGet|mget)\s*\(`, ObjectType: "RedisClient", MethodName: "mGet/mget", Description: "Redis MGET — multiple string values (possibly user-controlled cached data)", Assigns: "return"},
	{ID: "js.redis.lrange", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:lRange|lrange)\s*\(`, ObjectType: "RedisClient", MethodName: "lRange/lrange", Description: "Redis LRANGE — list slice (possibly user-controlled cached data)", Assigns: "return"},
	{ID: "js.redis.lindex", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:lIndex|lindex)\s*\(`, ObjectType: "RedisClient", MethodName: "lIndex/lindex", Description: "Redis LINDEX — list element (possibly user-controlled cached data)", Assigns: "return"},
	{ID: "js.redis.lpop", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:lPop|lpop)\s*\(`, ObjectType: "RedisClient", MethodName: "lPop/lpop", Description: "Redis LPOP — head list element (possibly user-controlled cached data)", Assigns: "return"},
	{ID: "js.redis.rpop", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:rPop|rpop)\s*\(`, ObjectType: "RedisClient", MethodName: "rPop/rpop", Description: "Redis RPOP — tail list element (possibly user-controlled cached data)", Assigns: "return"},
	{ID: "js.redis.smembers", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:sMembers|smembers)\s*\(`, ObjectType: "RedisClient", MethodName: "sMembers/smembers", Description: "Redis SMEMBERS — set members (possibly user-controlled cached data)", Assigns: "return"},
	{ID: "js.redis.srandmember", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:sRandMember|srandmember)\s*\(`, ObjectType: "RedisClient", MethodName: "sRandMember/srandmember", Description: "Redis SRANDMEMBER — random set member (possibly user-controlled cached data)", Assigns: "return"},
	{ID: "js.redis.spop", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:sPop|spop)\s*\(`, ObjectType: "RedisClient", MethodName: "sPop/spop", Description: "Redis SPOP — popped set member (possibly user-controlled cached data)", Assigns: "return"},
	{ID: "js.redis.zrange", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:zRange|zrange)\s*\(`, ObjectType: "RedisClient", MethodName: "zRange/zrange", Description: "Redis ZRANGE — sorted-set slice (possibly user-controlled cached data)", Assigns: "return"},
	{ID: "js.redis.zrangebyscore", Category: taint.SrcExternal, Pattern: `(?:redis|redisClient)\.(?:zRangeByScore|zrangebyscore)\s*\(`, ObjectType: "RedisClient", MethodName: "zRangeByScore/zrangebyscore", Description: "Redis ZRANGEBYSCORE — sorted-set range by score (possibly user-controlled cached data)", Assigns: "return"},

	// =================================================================
	// Mined from public MIT-licensed security-model data.
	// JS Models-as-Data extension data — Apollo, AWS SDK, axios, GraphQL,
	// SAP HANA clients, react-relay.
	// =================================================================
	{ID: "js.apollo.server", Category: taint.SrcExternal, Pattern: `new\s+(?:ApolloServer|ApolloServerBase)\s*\(`, ObjectType: "@apollo/server", MethodName: "ApolloServer/ApolloServerBase", Description: "Apollo Server constructor — the schema/resolver context object is attacker-influenced", Assigns: "return"},
	{ID: "js.aws.client.send", Category: taint.SrcDatabase, Pattern: `\.send\s*\(`, ObjectType: "@aws-sdk/client.Client", MethodName: "send", Description: "AWS SDK v3 Client.send() result — service/DB response data", Assigns: "return"},
	{ID: "js.aws.athena.get_query_results.promise", Category: taint.SrcDatabase, Pattern: `\.getQueryResults\s*\([^)]*\)\.promise\s*\(`, ObjectType: "aws-sdk.Athena", MethodName: "getQueryResults.promise", Description: "AWS Athena getQueryResults().promise() — query rows from untrusted user data", Assigns: "return"},
	{ID: "js.aws.s3.get_object.promise", Category: taint.SrcDatabase, Pattern: `\.getObject\s*\([^)]*\)\.promise\s*\(`, ObjectType: "aws-sdk.S3", MethodName: "getObject.promise", Description: "AWS S3 getObject().promise() — object content from untrusted bucket", Assigns: "return"},
	{ID: "js.aws.rds.execute_statement.promise", Category: taint.SrcDatabase, Pattern: `\.(?:executeStatement|batchExecuteStatement)\s*\([^)]*\)\.promise\s*\(`, ObjectType: "aws-sdk.RDSDataService", MethodName: "executeStatement/batchExecuteStatement.promise", Description: "AWS RDS executeStatement().promise() — DB rows; treat as untrusted in downstream sinks", Assigns: "return"},
	{ID: "js.aws.dynamodb.query.promise", Category: taint.SrcDatabase, Pattern: `\.(?:executeStatement|batchExecuteStatement|query|scan|getItem|batchGetItem)\s*\([^)]*\)\.promise\s*\(`, ObjectType: "aws-sdk.DynamoDB", MethodName: "executeStatement/batchExecuteStatement/query/scan/getItem/batchGetItem.promise", Description: "AWS DynamoDB query/scan/get result — second-order taint from stored data", Assigns: "return"},
	{ID: "js.axios.interceptor_response", Category: taint.SrcExternal, Pattern: `axios\.interceptors\.response\.use\s*\(`, ObjectType: "axios", MethodName: "interceptors.response.use", Description: "axios response interceptor callback — receives the remote response as its first argument", Assigns: "return"},
	{ID: "js.graphql.resolve", Category: taint.SrcExternal, Pattern: `resolve\s*:\s*(?:async\s+)?(?:function|\()`, ObjectType: "graphql", MethodName: "GraphQLObjectType.fields.resolve", Description: "GraphQL resolver function — first arg is the user-controlled args object", Assigns: "return"},
	{ID: "js.hana.exec.callback", Category: taint.SrcDatabase, Pattern: `\.exec\s*\(`, ObjectType: "@sap/hana-client", MethodName: "createConnection.exec", Description: "SAP HANA exec callback — second arg is rows from DB", Assigns: "return"},
	{ID: "js.hana.prepare.exec.callback", Category: taint.SrcDatabase, Pattern: `\.(?:execBatch|exec|execQuery)\s*\(`, ObjectType: "@sap/hana-client", MethodName: "createConnection.prepare.execBatch/exec/execQuery", Description: "SAP HANA prepared-statement exec — rows from DB", Assigns: "return"},
	{ID: "js.hdb.client.exec", Category: taint.SrcDatabase, Pattern: `\.(?:exec|execute)\s*\(`, ObjectType: "hdb", MethodName: "Client.exec/execute", Description: "hdb Client.exec/execute — DB rows from SAP HANA", Assigns: "return"},
	{ID: "js.hdb.prepare.exec", Category: taint.SrcDatabase, Pattern: `\.prepare\s*\([^)]*\)[\s\S]*?\.exec\s*\(`, ObjectType: "hdb", MethodName: "Client.prepare.exec", Description: "hdb prepared-statement exec — DB rows", Assigns: "return"},
	{ID: "js.hana.stream.create_proc_statement.exec", Category: taint.SrcDatabase, Pattern: `\.createProcStatement\s*\([^)]*\)[\s\S]*?\.exec\s*\(`, ObjectType: "@sap/hana-client/extension/Stream", MethodName: "createProcStatement.exec", Description: "SAP HANA stream createProcStatement.exec — DB rows", Assigns: "return"},
	{ID: "js.hdbext.load_procedure.callback", Category: taint.SrcDatabase, Pattern: `\.loadProcedure\s*\(`, ObjectType: "@sap/hdbext", MethodName: "loadProcedure", Description: "SAP hdbext loadProcedure callback — proc result rows", Assigns: "return"},
	{ID: "js.relay.use_fragment", Category: taint.SrcExternal, Pattern: `\buseFragment\s*\(`, ObjectType: "react-relay", MethodName: "useFragment", Description: "react-relay useFragment — remote GraphQL data (treat as untrusted)", Assigns: "return"},
	{ID: "js.relay.use_lazy_load_query", Category: taint.SrcExternal, Pattern: `\buseLazyLoadQuery\s*\(`, ObjectType: "react-relay", MethodName: "useLazyLoadQuery", Description: "react-relay useLazyLoadQuery — remote GraphQL data", Assigns: "return"},
	{ID: "js.relay.use_preloaded_query", Category: taint.SrcExternal, Pattern: `\busePreloadedQuery\s*\(`, ObjectType: "react-relay", MethodName: "usePreloadedQuery", Description: "react-relay usePreloadedQuery — remote GraphQL data", Assigns: "return"},
	{ID: "js.relay.use_client_query", Category: taint.SrcExternal, Pattern: `\buseClientQuery\s*\(`, ObjectType: "react-relay", MethodName: "useClientQuery", Description: "react-relay useClientQuery — remote GraphQL data", Assigns: "return"},
	{ID: "js.relay.use_refetchable_fragment", Category: taint.SrcExternal, Pattern: `\buseRefetchableFragment\s*\(`, ObjectType: "react-relay", MethodName: "useRefetchableFragment", Description: "react-relay useRefetchableFragment — remote GraphQL data", Assigns: "return"},
	{ID: "js.relay.use_pagination_fragment.data", Category: taint.SrcExternal, Pattern: `\busePaginationFragment\s*\(`, ObjectType: "react-relay", MethodName: "usePaginationFragment.data", Description: "react-relay usePaginationFragment.data — remote GraphQL data", Assigns: "return"},
	{ID: "js.relay.use_mutation.on_completed", Category: taint.SrcExternal, Pattern: `\buseMutation\s*\(`, ObjectType: "react-relay", MethodName: "useMutation.onCompleted", Description: "react-relay useMutation onCompleted callback receives server response", Assigns: "return"},
	{ID: "js.relay.use_subscription.on_next", Category: taint.SrcExternal, Pattern: `\buseSubscription\s*\(`, ObjectType: "react-relay", MethodName: "useSubscription.onNext", Description: "react-relay useSubscription onNext callback receives server-pushed data", Assigns: "return"},
	{ID: "js.relay.fetch_query.subscribe", Category: taint.SrcExternal, Pattern: `\bfetchQuery\s*\(`, ObjectType: "react-relay", MethodName: "fetchQuery.subscribe.next", Description: "react-relay fetchQuery subscribe.next — remote response", Assigns: "return"},
	{ID: "js.relay.read_fragment", Category: taint.SrcExternal, Pattern: `\breadFragment\s*\(`, ObjectType: "relay-runtime", MethodName: "readFragment", Description: "relay-runtime readFragment — remote GraphQL data", Assigns: "return"},

	// =================================================================
	// PR-BBjs: Framework-aware request handler sources.
	// Mirrors PR-BBpy. The existing js.express.* / js.fastify.* / js.koa.*
	// / js.hapi.* / js.nestjs.* entries above cover the dominant body /
	// params / query / headers shapes. This block fills the remaining
	// per-framework gaps — additional Request properties commonly used
	// in real-world Node code paths that flow into sinks (SSRF via
	// req.url, path traversal via req.originalUrl, log injection via
	// req.subdomains, etc.).
	// =================================================================

	// --- Express additional request properties ---
	{ID: "js.express.req.originalurl", Category: taint.SrcUserInput, Pattern: `req\.originalUrl`, ObjectType: "Request", MethodName: "originalUrl", Description: "Express req.originalUrl — full unmodified request URL (user-controlled)", Assigns: "return"},
	{ID: "js.express.req.protocol", Category: taint.SrcUserInput, Pattern: `req\.protocol`, ObjectType: "Request", MethodName: "protocol", Description: "Express req.protocol — http/https (spoofable via X-Forwarded-Proto)", Assigns: "return"},
	{ID: "js.express.req.subdomains", Category: taint.SrcUserInput, Pattern: `req\.subdomains`, ObjectType: "Request", MethodName: "subdomains", Description: "Express req.subdomains — derived from Host header (spoofable)", Assigns: "return"},
	{ID: "js.express.req.baseurl", Category: taint.SrcUserInput, Pattern: `req\.baseUrl`, ObjectType: "Request", MethodName: "baseUrl", Description: "Express req.baseUrl — path prefix where router was mounted (user-influenced via mount path)", Assigns: "return"},
	{ID: "js.express.req.header", Category: taint.SrcUserInput, Pattern: `req\.header\s*\(`, ObjectType: "Request", MethodName: "header", Description: "Express req.header(name) — alias of req.get(), header value retrieval", Assigns: "return"},
	{ID: "js.express.req.accepts", Category: taint.SrcUserInput, Pattern: `req\.accepts(?:Languages|Charsets|Encodings)?\s*\(`, ObjectType: "Request", MethodName: "accepts*", Description: "Express req.accepts*() — derived from Accept-* headers (user-controlled)", Assigns: "return"},

	// --- Fastify additional request properties ---
	{ID: "js.fastify.request.cookies", Category: taint.SrcUserInput, Pattern: `request\.cookies`, ObjectType: "FastifyRequest", MethodName: "cookies", Description: "Fastify request.cookies — parsed cookies (via @fastify/cookie plugin)", Assigns: "return"},
	{ID: "js.fastify.request.url", Category: taint.SrcUserInput, Pattern: `request\.url\b`, ObjectType: "FastifyRequest", MethodName: "url", Description: "Fastify request.url — raw request URL path+query (user-controlled)", Assigns: "return"},
	{ID: "js.fastify.request.hostname", Category: taint.SrcUserInput, Pattern: `request\.hostname`, ObjectType: "FastifyRequest", MethodName: "hostname", Description: "Fastify request.hostname — derived from Host header (spoofable)", Assigns: "return"},
	{ID: "js.fastify.request.ip", Category: taint.SrcUserInput, Pattern: `request\.ip\b|request\.ips\b`, ObjectType: "FastifyRequest", MethodName: "ip/ips", Description: "Fastify request.ip/ips — client IP (spoofable via X-Forwarded-For when trustProxy=true)", Assigns: "return"},
	{ID: "js.fastify.request.protocol", Category: taint.SrcUserInput, Pattern: `request\.protocol`, ObjectType: "FastifyRequest", MethodName: "protocol", Description: "Fastify request.protocol — http/https (spoofable via X-Forwarded-Proto)", Assigns: "return"},

	// --- Koa additional context properties ---
	{ID: "js.koa.ctx.request.headers", Category: taint.SrcUserInput, Pattern: `ctx\.request\.headers`, ObjectType: "KoaContext", MethodName: "request.headers", Description: "Koa ctx.request.headers — full request headers object", Assigns: "return"},
	{ID: "js.koa.ctx.request.url", Category: taint.SrcUserInput, Pattern: `ctx\.request\.url\b|ctx\.url\b`, ObjectType: "KoaContext", MethodName: "request.url/url", Description: "Koa ctx.url / ctx.request.url — request URL path+query (user-controlled)", Assigns: "return"},
	{ID: "js.koa.ctx.request.path", Category: taint.SrcUserInput, Pattern: `ctx\.request\.path\b|ctx\.path\b`, ObjectType: "KoaContext", MethodName: "request.path/path", Description: "Koa ctx.path / ctx.request.path — path component of URL (user-controlled)", Assigns: "return"},
	{ID: "js.koa.ctx.request.querystring", Category: taint.SrcUserInput, Pattern: `ctx\.request\.querystring\b|ctx\.querystring\b`, ObjectType: "KoaContext", MethodName: "request.querystring/querystring", Description: "Koa ctx.querystring / ctx.request.querystring — raw query string", Assigns: "return"},
	{ID: "js.koa.ctx.request.host", Category: taint.SrcUserInput, Pattern: `ctx\.request\.host\b|ctx\.host\b|ctx\.request\.hostname\b|ctx\.hostname\b`, ObjectType: "KoaContext", MethodName: "request.host/hostname", Description: "Koa ctx.host / ctx.hostname — Host header value (spoofable)", Assigns: "return"},
	{ID: "js.koa.ctx.request.origin", Category: taint.SrcUserInput, Pattern: `ctx\.request\.origin\b|ctx\.origin\b|ctx\.request\.href\b|ctx\.href\b`, ObjectType: "KoaContext", MethodName: "request.origin/href", Description: "Koa ctx.origin / ctx.href — request origin/href (derived from headers)", Assigns: "return"},
	{ID: "js.koa.ctx.request.ip", Category: taint.SrcUserInput, Pattern: `ctx\.request\.ip\b|ctx\.ip\b|ctx\.ips\b`, ObjectType: "KoaContext", MethodName: "request.ip/ips", Description: "Koa ctx.ip / ctx.ips — client IP (spoofable via X-Forwarded-For when proxy=true)", Assigns: "return"},

	// --- Hapi additional request properties ---
	{ID: "js.hapi.request.url", Category: taint.SrcUserInput, Pattern: `request\.url\b`, ObjectType: "HapiRequest", MethodName: "url", Description: "Hapi request.url — parsed URL object (user-controlled)", Assigns: "return"},
	{ID: "js.hapi.request.path", Category: taint.SrcUserInput, Pattern: `request\.path\b`, ObjectType: "HapiRequest", MethodName: "path", Description: "Hapi request.path — URL path component (user-controlled)", Assigns: "return"},
	{ID: "js.hapi.request.info", Category: taint.SrcUserInput, Pattern: `request\.info\.\w+`, ObjectType: "HapiRequest", MethodName: "info.*", Description: "Hapi request.info — remoteAddress/host/hostname/referrer (spoofable via headers/proxy)", Assigns: "return"},
	{ID: "js.hapi.request.mime", Category: taint.SrcUserInput, Pattern: `request\.mime\b`, ObjectType: "HapiRequest", MethodName: "mime", Description: "Hapi request.mime — Content-Type header value (user-controlled)", Assigns: "return"},
	{ID: "js.hapi.request.orig", Category: taint.SrcUserInput, Pattern: `request\.orig\.\w+`, ObjectType: "HapiRequest", MethodName: "orig.*", Description: "Hapi request.orig — original (pre-validated) payload/params/query/headers", Assigns: "return"},

	// --- Next.js (Pages router req.*) and App router NextRequest extras ---
	{ID: "js.nextjs.api.req.headers", Category: taint.SrcUserInput, Pattern: `req\.headers\b`, ObjectType: "NextApiRequest", MethodName: "headers", Description: "Next.js Pages API route req.headers", Assigns: "return"},
	{ID: "js.nextjs.api.req.cookies", Category: taint.SrcUserInput, Pattern: `req\.cookies\b`, ObjectType: "NextApiRequest", MethodName: "cookies", Description: "Next.js Pages API route req.cookies", Assigns: "return"},
	{ID: "js.nextjs.nextrequest.headers.get", Category: taint.SrcUserInput, Pattern: `(?:request|req)\.headers\.get\s*\(`, ObjectType: "NextRequest", MethodName: "headers.get", Description: "Next.js App Router NextRequest.headers.get(name) — typed Headers accessor", Assigns: "return"},
	{ID: "js.nextjs.nextrequest.cookies.get", Category: taint.SrcUserInput, Pattern: `(?:request|req)\.cookies\.get\s*\(`, ObjectType: "NextRequest", MethodName: "cookies.get", Description: "Next.js App Router NextRequest.cookies.get(name) — typed cookie accessor", Assigns: "return"},
	{ID: "js.nextjs.nextrequest.formdata", Category: taint.SrcUserInput, Pattern: `(?:request|req)\.formData\s*\(`, ObjectType: "NextRequest", MethodName: "formData", Description: "Next.js App Router NextRequest.formData() — form submission data (Web API surface)", Assigns: "return"},

	// --- NestJS additional decorators ---
	// We already cover @Query/@Param/@Body/@Headers — extend with the
	// remaining first-class request-binding decorators that show up
	// throughout NestJS controllers.
	{ID: "js.nestjs.req", Category: taint.SrcUserInput, Pattern: `@Req\s*\(\s*\)|@Request\s*\(\s*\)`, ObjectType: "NestJS", MethodName: "@Req/@Request", Description: "NestJS @Req()/@Request() parameter decorator — injects the underlying Express/Fastify Request", Assigns: "return"},
	{ID: "js.nestjs.session", Category: taint.SrcUserInput, Pattern: `@Session\s*\(\s*\)`, ObjectType: "NestJS", MethodName: "@Session", Description: "NestJS @Session() parameter decorator — session object (often holds user-controlled data)", Assigns: "return"},
	{ID: "js.nestjs.hostparam", Category: taint.SrcUserInput, Pattern: `@HostParam\s*\(`, ObjectType: "NestJS", MethodName: "@HostParam", Description: "NestJS @HostParam() parameter decorator — sub-domain parameter binding (derived from Host header)", Assigns: "return"},
	{ID: "js.nestjs.ip", Category: taint.SrcUserInput, Pattern: `@Ip\s*\(\s*\)`, ObjectType: "NestJS", MethodName: "@Ip", Description: "NestJS @Ip() parameter decorator — client IP address (spoofable via proxy headers)", Assigns: "return"},
	{ID: "js.nestjs.uploadedfile", Category: taint.SrcUserInput, Pattern: `@UploadedFile\s*\(|@UploadedFiles\s*\(`, ObjectType: "NestJS", MethodName: "@UploadedFile/@UploadedFiles", Description: "NestJS @UploadedFile()/@UploadedFiles() parameter decorator — multipart file upload (user-controlled content/filename)", Assigns: "return"},
}
