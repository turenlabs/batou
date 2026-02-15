package languages

import "github.com/turenio/gtss/internal/taint"

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

	// URL/Location sources
	{ID: "js.url.constructor", Category: taint.SrcUserInput, Pattern: `new\s+URL\s*\(`, ObjectType: "URL", MethodName: "URL", Description: "URL constructor with user-controlled input", Assigns: "return"},
	{ID: "js.url.searchparams", Category: taint.SrcUserInput, Pattern: `URLSearchParams`, ObjectType: "URLSearchParams", MethodName: "URLSearchParams", Description: "URL search parameters", Assigns: "return"},
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
	{ID: "js.nextjs.getserversideprops.context", Category: taint.SrcUserInput, Pattern: `context\.(query|params|req)`, ObjectType: "GetServerSidePropsContext", MethodName: "context", Description: "Next.js getServerSideProps context params/query", Assigns: "return"},
	{ID: "js.nextjs.searchparams", Category: taint.SrcUserInput, Pattern: `searchParams`, ObjectType: "PageProps", MethodName: "searchParams", Description: "Next.js App Router searchParams prop", Assigns: "return"},
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
	{ID: "js.localstorage.getitem", Category: taint.SrcExternal, Pattern: `localStorage\.getItem\s*\(`, ObjectType: "localStorage", MethodName: "getItem", Description: "localStorage data (potentially tampered)", Assigns: "return"},
	{ID: "js.sessionstorage.getitem", Category: taint.SrcExternal, Pattern: `sessionStorage\.getItem\s*\(`, ObjectType: "sessionStorage", MethodName: "getItem", Description: "sessionStorage data (potentially tampered)", Assigns: "return"},

	// AWS Lambda event source
	{ID: "js.aws.lambda.event", Category: taint.SrcExternal, Pattern: `exports\.handler\s*=\s*async\s*\(\s*event|module\.exports\.handler\s*=\s*async\s*\(\s*event`, ObjectType: "aws-lambda", MethodName: "Lambda handler event", Description: "AWS Lambda event data from external trigger", Assigns: "return"},
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
}
