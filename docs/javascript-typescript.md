# JavaScript/TypeScript Security Scanning

## Overview

GTSS provides comprehensive security scanning for JavaScript and TypeScript codebases. Coverage spans server-side frameworks (Express, Fastify, Hapi, Nest.js, Next.js), client-side DOM APIs, React patterns, and common npm ecosystem libraries. Both JavaScript and TypeScript share the same taint analysis definitions, with TypeScript IDs prefixed `ts.` instead of `js.`.

Analysis runs in three layers:

1. **Regex rules** -- pattern-based detection of known-vulnerable code constructs
2. **Taint analysis** -- tracks data flow from user-controlled sources to dangerous sinks, accounting for sanitizers
3. **Interprocedural call graph** -- follows taint across function boundaries using persistent call graphs

## Detection

GTSS identifies JavaScript and TypeScript files by extension:

| Extension | Language       |
|-----------|---------------|
| `.js`     | JavaScript     |
| `.jsx`    | JavaScript     |
| `.mjs`    | JavaScript     |
| `.cjs`    | JavaScript     |
| `.ts`     | TypeScript     |
| `.tsx`    | TypeScript     |
| `.mts`    | TypeScript     |

Files with these extensions are automatically scanned. Binary files, images, fonts, lock files, and generated/vendored files are excluded.

## Taint Analysis Coverage

### Sources (User Input Entry Points)

#### Express / HTTP Request

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.express.req.query` | `req.query` | Express query parameters |
| `js.express.req.params` | `req.params` | Express route parameters |
| `js.express.req.body` | `req.body` | Express request body |
| `js.express.req.headers` | `req.headers` | Express request headers |
| `js.express.req.cookies` | `req.cookies` | Express request cookies |
| `js.express.req.url` | `req.url` | Express request URL |
| `js.express.req.path` | `req.path` | Express request path |

#### Destructured Express Parameters

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.express.destructured.query` | `{ query }` | Destructured query parameters |
| `js.express.destructured.params` | `{ params }` | Destructured route parameters |
| `js.express.destructured.body` | `{ body }` | Destructured request body |
| `js.express.destructured.file` | `{ file }` | Destructured file upload |
| `js.express.destructured.cookies` | `{ cookies }` | Destructured cookies |

#### Bare Property Access (Post-Destructuring)

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.express.bare.query` | `query.foo` | Bare query property access |
| `js.express.bare.params` | `params.foo` | Bare params property access |
| `js.express.bare.body` | `body.foo` | Bare body property access |

#### DOM / Browser Sources

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.dom.document.location` | `document.location` | Document location |
| `js.dom.window.location` | `window.location` | Window location |
| `js.dom.location.hash` | `location.hash` | URL hash fragment |
| `js.dom.location.search` | `location.search` | URL query string |
| `js.dom.document.cookie` | `document.cookie` | Document cookies |
| `js.dom.getelementbyid.value` | `document.getElementById(...).value` | DOM input field value |
| `js.dom.innerhtml.read` | `.innerHTML` (read) | innerHTML as input |
| `js.dom.textcontent.read` | `.textContent` (read) | textContent as input |
| `js.dom.event.target.value` | `event.target.value` | Event target value (React/DOM) |

#### URL / Location

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.url.constructor` | `new URL(...)` | URL constructor |
| `js.url.searchparams` | `URLSearchParams` | URL search parameters |

#### Next.js

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.nextjs.getserversideprops.context` | `context.query`, `context.params`, `context.req` | getServerSideProps context |
| `js.nextjs.searchparams` | `searchParams` | App Router searchParams prop |
| `js.nextjs.api.req.query` | `req.query` | API route query |
| `js.nextjs.api.req.body` | `req.body` | API route body |

#### Nest.js

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.nestjs.query` | `@Query()` | Query decorator |
| `js.nestjs.param` | `@Param()` | Param decorator |
| `js.nestjs.body` | `@Body()` | Body decorator |
| `js.nestjs.headers` | `@Headers()` | Headers decorator |

#### Fastify

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.fastify.request.params` | `request.params` | Route parameters |
| `js.fastify.request.query` | `request.query` | Query string |
| `js.fastify.request.body` | `request.body` | Request body |

#### Hapi

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.hapi.request.payload` | `request.payload` | Request payload |
| `js.hapi.request.params` | `request.params` | Route parameters |
| `js.hapi.request.query` | `request.query` | Query string |

#### GraphQL

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.graphql.resolver.args` | `(parent, args, ...)` | Resolver args parameter |

#### Network / WebSocket

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.fetch.response` | `fetch(...)` | Fetch API response |
| `js.axios.response` | `axios(...)` | Axios response |
| `js.websocket.onmessage` | `.onmessage =` | WebSocket message data |
| `js.socketio.on.data` | `socket.on(...)` | Socket.io event data |

#### CLI / Environment

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.process.argv` | `process.argv` | Command-line arguments |
| `js.process.env` | `process.env` | Environment variables |

#### File System

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.fs.readfilesync` | `fs.readFileSync(...)` | Synchronous file read |
| `js.fs.readfile` | `fs.readFile(...)` | Asynchronous file read |

#### External / Storage

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.postmessage.event.data` | `addEventListener('message', ...)` | postMessage cross-origin data |
| `js.localstorage.getitem` | `localStorage.getItem(...)` | localStorage data |
| `js.sessionstorage.getitem` | `sessionStorage.getItem(...)` | sessionStorage data |

#### Cloud Provider Sources

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `js.aws.lambda.event` | `exports.handler = async (event` | AWS Lambda event |
| `js.aws.sqs.receive` | `.receiveMessage(...)` | AWS SQS message |
| `js.aws.s3.getobject` | `.getObject(...)` | AWS S3 object |
| `js.gcp.cloudfunctions.event` | `exports.fn = (req, res)` | GCP Cloud Functions |
| `js.gcp.pubsub.pull` | `subscription.on('message', ...)` | GCP Pub/Sub message |

---

### Sinks (Dangerous Functions)

#### SQL Injection (CWE-89)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `js.sql.query` | `.query(...)` | Critical |
| `js.sql.execute` | `.execute(...)` | Critical |
| `js.knex.raw` | `knex.raw(...)` | Critical |
| `js.sequelize.query` | `sequelize.query(...)` | Critical |
| `js.prisma.queryraw` | `$queryRaw(...)` | Critical |
| `js.prisma.executeraw` | `$executeRaw(...)` | Critical |
| `js.prisma.queryrawunsafe` | `$queryRawUnsafe(...)` | Critical |
| `js.prisma.executerawunsafe` | `$executeRawUnsafe(...)` | Critical |

#### NoSQL / MongoDB Injection (CWE-943)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `js.mongoose.where` | `.$where(...)` | Critical |
| `js.mongoose.where.concat` | `$where: '...' +` | Critical |
| `js.mongoose.where.template` | `` $where: `...${` `` | Critical |
| `js.mongoose.find.tainted` | `.find(...)` | High |
| `js.mongoose.findone` | `.findOne(...)` | High |
| `js.mongoose.aggregate.tainted` | `.aggregate(...)` | High |
| `js.mongoose.update` | `.update(...)` | High |
| `js.mongoose.updateone` | `.updateOne(...)` | High |
| `js.mongoose.updatemany` | `.updateMany(...)` | High |
| `js.mongoose.deleteone` | `.deleteOne(...)` | High |
| `js.mongoose.deletemany` | `.deleteMany(...)` | High |
| `js.mongoose.findoneandupdate` | `.findOneAndUpdate(...)` | High |
| `js.mongoose.findoneanddelete` | `.findOneAndDelete(...)` | High |
| `js.mongoose.insertone` | `.insertOne(...)` | High |
| `js.mongoose.insertmany` | `.insertMany(...)` | High |
| `js.mongoose.replaceone` | `.replaceOne(...)` | High |

#### Command Injection (CWE-78)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `js.child_process.exec` | `child_process.exec(...)` | Critical |
| `js.child_process.execsync` | `child_process.execSync(...)` | Critical |
| `js.child_process.spawn` | `child_process.spawn(...)` | Critical |
| `js.exec.short` | `exec(...)` | Critical |
| `js.execsync.short` | `execSync(...)` | Critical |
| `js.spawn.short` | `spawn(...)` | Critical |
| `js.child_process.execfile` | `execFile(...)` | Critical |
| `js.child_process.fork` | `fork(...)` | High |
| `js.dockerode.exec` | `container.exec(...)` | Critical |

#### Code Evaluation (CWE-94)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `js.eval` | `eval(...)` | Critical |
| `js.new.function` | `new Function(...)` | Critical |
| `js.settimeout.string` | `setTimeout("...")` | Critical |
| `js.setinterval.string` | `setInterval("...")` | Critical |
| `js.vm.runincontext` | `vm.runInContext(...)` | Critical |
| `js.vm.runinnewcontext` | `vm.runInNewContext(...)` | Critical |
| `js.vm.runinthiscontext` | `vm.runInThisContext(...)` | Critical |
| `js.vm.script` | `new vm.Script(...)` | Critical |
| `js.redis.eval` | `.eval(...)` (Redis Lua) | Critical |
| `js.express.res.render` | `res.render(...)` | High |

#### XSS / HTML Output (CWE-79)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `js.dom.innerhtml.write` | `.innerHTML =` | High |
| `js.dom.document.write` | `document.write(...)` | High |
| `js.react.dangerouslysetinnerhtml` | `dangerouslySetInnerHTML` | High |
| `js.express.res.send` | `res.send(...)` | High |
| `js.express.res.write` | `res.write(...)` | High |

#### File Operations / Path Traversal (CWE-22)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `js.fs.writefile` | `fs.writeFile(...)` | High |
| `js.fs.readfile.sink` | `fs.readFile(...)` | High |
| `js.fs.unlink` | `fs.unlink(...)` | High |
| `js.fs.createreadstream` | `fs.createReadStream(...)` | High |
| `js.express.res.sendfile` | `res.sendFile(...)` | High |
| `js.express.res.download` | `res.download(...)` | High |

#### Redirect (CWE-601)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `js.express.res.redirect` | `res.redirect(...)` | High |
| `js.dom.window.location.assign` | `window.location =` | High |
| `js.dom.location.href.assign` | `location.href =` | High |

#### SSRF (CWE-918)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `js.fetch.ssrf` | `fetch(...)` | High |
| `js.axios.get.ssrf` | `axios.get(...)` | High |
| `js.http.get.ssrf` | `http.get(...)` | High |
| `js.request.ssrf` | `request(...)` | High |
| `js.dns.lookup` | `dns.lookup(...)` / `dns.resolve(...)` | High |

#### Deserialization (CWE-502)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `js.node.serialize` | `unserialize(...)` / `deserialize(...)` | Critical |
| `js.yaml.load` | `yaml.load(...)` | High |
| `js.json.parse` | `JSON.parse(...)` | Low |

#### Template Injection (CWE-1336)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `js.ejs.render` | `ejs.render(...)` | High |
| `js.pug.render` | `pug.render(...)` | High |
| `js.handlebars.compile` | `Handlebars.compile(...)` | High |

#### Cryptographic Weaknesses

| Sink ID | Pattern | Severity | CWE |
|---------|---------|----------|-----|
| `js.crypto.createhash.md5` | createHash with MD5 | Medium | CWE-328 |
| `js.crypto.createhash.sha1` | createHash with SHA-1 | Medium | CWE-328 |
| `js.crypto.createcipheriv.weak` | createCipheriv with deprecated/broken algorithms | High | CWE-327 |
| `js.crypto.math_random` | `Math.random()` | High | CWE-338 |
| `js.jwt.decode.noverify` | `jwt.decode(...)` | High | CWE-345 |
| `js.jwt.verify.none_algo` | jwt.verify with 'none' algorithm | Critical | CWE-345 |

#### Header / Email Injection

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `js.express.res.setheader` | `res.setHeader(...)` | Medium |
| `js.express.res.header` | `res.header(...)` | Medium |
| `js.nodemailer.sendmail` | `transporter.sendMail(...)` | High |

#### Log Injection (CWE-117)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `js.console.log` | `console.log(...)` | Medium |
| `js.console.warn` | `console.warn(...)` | Medium |
| `js.console.error` | `console.error(...)` | Medium |
| `js.console.info` | `console.info(...)` | Medium |
| `js.winston.log` | `winston.log/info/warn/error(...)` | Medium |
| `js.pino.log` | `pino.info/warn/error(...)` | Medium |
| `js.bunyan.log` | `bunyan.info/warn/error(...)` | Medium |
| `js.logger.generic` | `logger.info/warn/error(...)` | Medium |

#### Other

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `js.redis.sendcommand` | `.sendCommand(...)` | High |
| `js.kafkajs.send` | `producer.send(...)` | Medium |

---

### Sanitizers (Safe Transformations)

#### HTML / XSS Sanitizers

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `js.dompurify.sanitize` | `DOMPurify.sanitize(...)` | HTML output |
| `js.sanitize.html` | `sanitizeHtml(...)` | HTML output |
| `js.xss.filter` | `xss(...)` | HTML output |
| `js.isomorphic-dompurify` | `sanitize(...)` (DOMPurify) | HTML output |
| `js.escapehtml` | `escapeHtml(...)` | HTML output |
| `js.validator.escape` | `validator.escape(...)` | HTML output |
| `js.encodeuricomponent` | `encodeURIComponent(...)` | HTML output, redirect |
| `js.encodeuri` | `encodeURI(...)` | Redirect |

#### SQL Parameterization

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `js.knex.parameterized` | `knex(...).where(...)` | SQL query |
| `js.prisma.tagged.template` | `` Prisma.sql`...` `` | SQL query |
| `js.sequelize.bind` | `.query(..., { replacements/bind })` | SQL query |
| `js.mongo.sanitize` | `mongo-sanitize` / `express-mongo-sanitize` | SQL/NoSQL query |

#### Schema Validation

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `js.zod.parse` | `schema.parse(...)` | SQL, command, HTML |
| `js.zod.safeparse` | `.safeParse(...)` | SQL, command, HTML |
| `js.joi.validate` | `Joi.validate(...)` / `Joi.attempt(...)` | SQL, command, HTML |
| `js.yup.validate` | `.validate(...)` | SQL, command, HTML |
| `js.ajv.validate` | `ajv.validate(...)` | SQL, command, HTML |
| `js.class-validator` | `@IsString()`, `@IsInt()`, etc. | SQL, command |
| `js.nestjs.validationpipe` | `ValidationPipe` | SQL, command, HTML |
| `js.express-validator` | `check(...)`, `body(...)`, `param(...)` | SQL, command, HTML, file |

#### Type Coercion

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `js.parseint` | `parseInt(...)` | SQL query, command |

#### Path Safety

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `js.path.basename` | `path.basename(...)` | File write/read |

#### URL Validation

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `js.validator.isurl` | `validator.isURL(...)` | URL fetch, redirect |
| `js.validator.isip` | `validator.isIP(...)` | URL fetch |
| `js.url.parse.hostname` | `new URL(...).hostname` | URL fetch, redirect |

#### Crypto / Auth

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `js.crypto.bcrypt.hash` | `bcrypt.hash(...)` / `bcrypt.hashSync(...)` | Crypto |
| `js.crypto.bcrypt.compare` | `bcrypt.compare(...)` / `bcrypt.compareSync(...)` | Crypto |
| `js.crypto.timingsafeequal` | `crypto.timingSafeEqual(...)` | Crypto |
| `js.crypto.randombytes` | `crypto.randomBytes(...)` / `crypto.randomUUID(...)` | Crypto |
| `js.csrf.middleware` | `csurf(...)` / `csrfProtection` | Crypto |

## Rule Coverage

The following regex-based rules apply to JavaScript and TypeScript files. Rules are organized by category.

### Injection

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-INJ-001 | SQL Injection | Critical | SQL queries built via string concatenation or template literal interpolation |
| GTSS-INJ-002 | Command Injection | Critical | Shell commands constructed with unsanitized variables |
| GTSS-INJ-003 | Code Injection | High | `eval()`, `Function()` constructor, and dynamic code execution |
| GTSS-INJ-004 | LDAP Injection | High | LDAP queries built with string concatenation |
| GTSS-INJ-005 | Template Injection | High | User input rendered directly in server-side templates (EJS, Pug, Handlebars) |
| GTSS-INJ-006 | XPath Injection | Medium | XPath queries built with string concatenation |
| GTSS-INJ-007 | NoSQL Injection | High | MongoDB `$where` with concatenation, unsanitized `$regex`, `JSON.parse` in queries |
| GTSS-INJ-008 | GraphQL Injection | High | GraphQL queries built via string concatenation instead of variables |
| GTSS-INJ-009 | HTTP Header Injection | High | HTTP response headers set with user-controlled input allowing CRLF injection |

### XSS

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-XSS-001 | innerHTML Usage | High | `innerHTML`/`outerHTML` assignments with dynamic content |
| GTSS-XSS-002 | dangerouslySetInnerHTML | High | React `dangerouslySetInnerHTML` usage |
| GTSS-XSS-003 | document.write | Medium | `document.write`/`writeln` calls with dynamic content |
| GTSS-XSS-004 | Unescaped Template Output | High | Template engines outputting unescaped content |
| GTSS-XSS-005 | DOM Manipulation | High | Risky DOM APIs with user-controlled data |
| GTSS-XSS-006 | Response Header Injection | High | HTTP response headers set with unsanitized input |
| GTSS-XSS-007 | URL Scheme Injection | High | `javascript:` protocol in URLs and dynamic href/src |
| GTSS-XSS-009 | Missing Content-Type | Medium | HTML content sent without Content-Type header |
| GTSS-XSS-010 | JSON Content-Type XSS | Medium | JSON with user data sent without `application/json` Content-Type |
| GTSS-XSS-011 | Reflected XSS | High | Direct reflection of request parameters in HTTP response body |

### Path Traversal

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-TRV-001 | Path Traversal | Critical | File operations with unsanitized user input allowing `../` attacks |
| GTSS-TRV-005 | Template Path Injection | High | Template name/path from user input (JS/TS/Python only) |
| GTSS-TRV-006 | Prototype Pollution | High | Spreading `req.body` into objects (JS/TS only) |
| GTSS-TRV-007 | Express sendFile Path | High | `res.sendFile()`/`res.download()` with variable path (JS/TS only) |
| GTSS-TRV-008 | Null Byte File Path | Medium | File operations lacking null byte sanitization |
| GTSS-TRV-009 | Render Options Injection | High | User input spread into `res.render()` options (JS/TS only) |
| GTSS-TRV-010 | Zip Slip Path Traversal | Critical | Archive extraction where entry names construct file paths without target directory validation |

### Cryptography

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-CRY-001 | Weak Hashing | High | MD5 or SHA-1 used for security purposes |
| GTSS-CRY-002 | Insecure Random | High | Non-cryptographic random in security contexts |
| GTSS-CRY-003 | Weak Cipher | Critical | Broken or deprecated encryption algorithms and non-authenticated block modes |
| GTSS-CRY-004 | Hardcoded IV | High | Hardcoded initialization vectors and nonces |
| GTSS-CRY-005 | Insecure TLS | Critical | Disabled TLS verification or deprecated TLS 1.0/1.1 |
| GTSS-CRY-006 | Weak Key Size | High | RSA below 2048 bits, weak curves, small symmetric keys |
| GTSS-CRY-008 | Math.random() Security | Critical | `Math.random()` in token/session/password/CSRF generation (JS/TS only) |
| GTSS-CRY-012 | Hardcoded Key | Critical | Cryptographic keys embedded in source code |
| GTSS-CRY-013 | Unauthenticated Encryption | High | CBC mode without HMAC/MAC authentication |
| GTSS-CRY-014 | Insecure RSA Padding | High | PKCS#1 v1.5 padding (Bleichenbacher-vulnerable) |
| GTSS-CRY-015 | Weak Password Hash | Critical | Fast hash functions for password storage instead of bcrypt/scrypt/Argon2 |
| GTSS-CRY-017 | Timing-Unsafe Compare | Medium | `==`/`===` used to compare secrets, tokens, hashes, or signatures instead of constant-time comparison |

### Secrets

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-SEC-001 | Hardcoded Password | Critical | Passwords and credentials as string literals |
| GTSS-SEC-005 | JWT Secret | Critical | Hardcoded JWT signing secrets |

### Authentication

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-AUTH-001 | Hardcoded Credential Check | Critical | Auth checks against hardcoded string values |
| GTSS-AUTH-002 | Missing Auth Check | Medium | HTTP handlers lacking authentication middleware |
| GTSS-AUTH-003 | CORS Wildcard | High | Overly permissive CORS with wildcard origins |
| GTSS-AUTH-004 | Session Fixation | High | Missing session ID regeneration after login |
| GTSS-AUTH-005 | Weak Password Policy | Medium | Password validation with weak requirements |
| GTSS-AUTH-006 | Insecure Cookie | High | Cookies without Secure, HttpOnly, or SameSite flags |

### SSRF

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-SSRF-001 | URL From User Input | High | HTTP requests with user-derived URLs |
| GTSS-SSRF-003 | DNS Rebinding | Medium | Hostname resolved then used in separate request step |
| GTSS-SSRF-004 | Redirect Following | Medium | HTTP clients following redirects with user-controlled URLs |

### Generic

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-GEN-001 | Debug Mode Enabled | High | Debug/dev mode in production configuration |
| GTSS-GEN-002 | Unsafe Deserialization | Critical | Deserialization of untrusted data (node-serialize, yaml.load) |
| GTSS-GEN-004 | Open Redirect | High | HTTP redirects to user-controlled URLs |
| GTSS-GEN-005 | Log Injection | Medium | Unsanitized user input in log statements |
| GTSS-GEN-006 | Race Condition | Medium | TOCTOU patterns without synchronization |
| GTSS-GEN-007 | Mass Assignment | High | All fields from user input accepted for updates |
| GTSS-GEN-008 | Code As String Eval | High | Dangerous calls hidden in eval/vm/Function strings (JS/TS only) |
| GTSS-GEN-009 | XML Parser Misconfig | High | XML parsers with external entity processing enabled |

### Logging

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-LOG-001 | Unsanitized Log Input | High | User input passed directly to logging functions |
| GTSS-LOG-002 | CRLF Log Injection | High | String concatenation/interpolation with user input in log calls |
| GTSS-LOG-003 | Sensitive Data in Logs | Medium | Passwords, tokens, API keys, or PII in log statements |

### Input Validation

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-VAL-001 | Direct Param Usage | High | Request parameters used without any validation nearby |
| GTSS-VAL-002 | Missing Type Coercion | Medium | User input used where a specific type is expected |
| GTSS-VAL-003 | Missing Length Validation | Medium | User input in DB/storage operations without length checks |
| GTSS-VAL-004 | Missing Allowlist Validation | Medium | User input as object keys without allowlist |

### XXE

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-XXE-002 | JavaScript XXE | Critical | XML parsing with external entity expansion enabled (libxmljs with `noent:true`, fast-xml-parser with `processEntities:true`, DOMParser, XML parsing with request input) |

### NoSQL Injection

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-NOSQL-001 | MongoDB $where Injection | Critical | `$where` operator with string interpolation or concatenation enabling server-side JavaScript execution |
| GTSS-NOSQL-002 | MongoDB Operator Injection | High | User input passed as MongoDB query operators (`$gt`, `$ne`, etc.) enabling query manipulation |
| GTSS-NOSQL-003 | MongoDB Raw Query Injection | High | Raw MongoDB queries with user input in `$regex`, aggregation pipelines, `mapReduce`, or server-side eval |

### Deserialization

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-DESER-004 | setTimeout/setInterval String Exec | High | `setTimeout`/`setInterval` with string arguments containing user input (implicit `eval()`) |

### Prototype Pollution

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-PROTO-001 | Prototype Pollution via Merge | High | Deep merge/extend/`Object.assign`/spread operations with user-controlled input (lodash merge, deepmerge, etc.) |
| GTSS-PROTO-002 | Direct Prototype Assignment | High | Direct access to `__proto__` or `constructor.prototype` properties, dynamic property assignment with user-controlled keys |

### Mass Assignment

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-MASS-001 | JavaScript Mass Assignment | High | `Object.assign(model, req.body)`, spread into models, ORM update with raw body, model constructor with raw user input |

### CORS

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-CORS-001 | CORS Wildcard with Credentials | Medium | CORS configuration with wildcard origin (`*`) and credentials enabled |
| GTSS-CORS-002 | CORS Reflected Origin | High | Request `Origin` header reflected in `Access-Control-Allow-Origin` without validation |

### GraphQL

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-GQL-001 | GraphQL Introspection Enabled | Medium | GraphQL schema with introspection enabled, exposing the full API schema |
| GTSS-GQL-002 | No Query Depth Limiting | Medium | GraphQL server without query depth limiting or complexity analysis (DoS risk) |

### Misconfiguration

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-MISC-001 | Debug Mode | Medium | `NODE_ENV` hardcoded to development, or generic debug mode flags enabled |
| GTSS-MISC-002 | Error Disclosure | Low | Error stack traces, messages, or raw error objects sent in HTTP responses |

### Redirect

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-REDIR-001 | Server Redirect with User Input | Medium | `res.redirect()` with user-controlled URL (open redirect) |
| GTSS-REDIR-002 | Bypassable URL Allowlist | Medium | URL validation via `url.includes()`, `url.indexOf()`, or `url.startsWith('http')` that can be bypassed |

### Express Framework Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-FW-EXPRESS-001 | Missing Helmet | Medium | Express application without Helmet middleware for security headers (CSP, HSTS, X-Frame-Options) |
| GTSS-FW-EXPRESS-002 | Insecure Session Config | Medium | Express session with `secure: false`, `httpOnly: false`, or `sameSite: 'none'` |
| GTSS-FW-EXPRESS-003 | Stack Trace Leak | Medium | Express error handler leaking stack traces or error messages to clients |
| GTSS-FW-EXPRESS-004 | Dynamic Require | Critical | `require()` or `import()` with user-controlled input enabling arbitrary module loading |
| GTSS-FW-EXPRESS-005 | Sensitive Static Directory | High | `express.static()` serving directories that expose sensitive files (`.git`, `.env`, root, `node_modules`) |
| GTSS-FW-EXPRESS-006 | Trust Proxy Misconfiguration | Medium | `app.set('trust proxy', true)` trusting all proxies, allowing IP spoofing via `X-Forwarded-For` |
| GTSS-FW-EXPRESS-007 | Missing Session Expiration | Medium | Session configuration without `maxAge` or `expires`, creating sessions that never expire |
| GTSS-FW-EXPRESS-008 | Process.env Leak | High | `process.env` sent directly in client responses, exposing secrets and API keys |

### React Framework Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-FW-REACT-001 | React SSR Unsanitized | High | `renderToString`/`renderToStaticMarkup` in files handling user input without sanitization (XSS risk) |
| GTSS-FW-REACT-002 | React Ref innerHTML | High | `ref.current.innerHTML` assignment bypassing React's built-in XSS protection |
| GTSS-FW-REACT-003 | React Prop Spreading | Medium | Spreading user-controlled data as React component props (can inject `dangerouslySetInnerHTML`, event handlers) |
| GTSS-FW-REACT-004 | Dynamic Script/Iframe | High | `createElement('script'/'iframe')` or JSX `<script>`/`<iframe>` with dynamic `src`/`srcdoc` attributes |

## Example Detections

### SQL Injection via Template Literal

GTSS flags SQL queries built with template literal interpolation. This triggers GTSS-INJ-001 (regex layer) and the taint engine traces `req.body.email` as a source flowing into `pool.query` as a sink.

```typescript
// VULNERABLE -- GTSS-INJ-001 + taint: js.express.req.body -> js.sql.query
export async function findUser(req: Request, res: Response): Promise<void> {
  const email = req.body.email;
  const password = req.body.password;

  const [rows] = await pool.query(
    `SELECT * FROM Users WHERE email = '${email}' AND password = '${password}'`
  );

  res.json({ user: (rows as any[])[0] });
}
```

### Reflected XSS via res.send

User input reflected directly in an HTML response without escaping. Triggers GTSS-XSS-011 and taint flow from `req.query.q` to `res.send`.

```typescript
// VULNERABLE -- GTSS-XSS-011 + taint: js.express.req.query -> js.express.res.send
export function searchHandler(req: Request, res: Response): void {
  const query = req.query.q as string;

  res.send(`
    <html>
      <body>
        <p>You searched for: ${query}</p>
      </body>
    </html>
  `);
}
```

### Command Injection via child_process

String concatenation with user input passed to a shell command execution function. Triggers GTSS-INJ-002 and taint flow from `req.query.host` to the command sink.

```typescript
// VULNERABLE -- GTSS-INJ-002 + taint: js.express.req.query -> js.child_process.exec
import { exec } from 'child_process';

export function pingHost(req: Request, res: Response): void {
  const host = req.query.host as string;

  exec('ping -c 3 ' + host, (error, stdout, stderr) => {
    res.json({ output: stdout });
  });
}
```

## Safe Patterns

### Parameterized SQL Queries

Using bind parameters or ORM query builders prevents SQL injection. GTSS recognizes Sequelize replacements, mysql2 placeholders, Prisma tagged templates, and Knex parameterized queries as sanitizers.

```typescript
// SAFE -- Sequelize replacements neutralize js.sql.query sink
const products = await sequelize.query(
  'SELECT * FROM Products WHERE name LIKE :search',
  {
    replacements: { search: `%${criteria}%` },
    type: QueryTypes.SELECT,
  }
);

// SAFE -- mysql2 ? placeholder parameterization
const [rows] = await pool.query(
  'SELECT * FROM Users WHERE id = ?',
  [userId]
);
```

### HTML Escaping and Sanitization

Using DOMPurify, escape-html, or other sanitization libraries before rendering user content into HTML. GTSS recognizes these as sanitizers that neutralize HTML output sinks.

```typescript
// SAFE -- escapeHtml neutralizes XSS sink
import escapeHtml from 'escape-html';

const safeQuery = escapeHtml(query);
res.send(`<p>You searched for: ${safeQuery}</p>`);

// SAFE -- DOMPurify sanitizes HTML content
import DOMPurify from 'dompurify';

const cleanHtml = DOMPurify.sanitize(userContent);
res.json({ html: cleanHtml });
```

### Safe Command Execution

Using `execFile` or `spawn` with argument arrays instead of shell string concatenation, combined with input validation.

```typescript
// SAFE -- execFile with separate arguments array, no shell interpretation
import { execFile } from 'child_process';

if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
  res.status(400).json({ error: 'Invalid hostname format' });
  return;
}

execFile('ping', ['-c', '3', host], (error, stdout, stderr) => {
  res.json({ output: stdout });
});
```

## Limitations

The following are known gaps and constraints in GTSS JavaScript/TypeScript coverage:

- **No type system analysis.** GTSS uses regex and pattern matching, not the TypeScript compiler. It cannot resolve types, interfaces, or generics. Taint through complex generic wrapper functions may be missed.

- **No module resolution.** Import paths are not followed. If a source is defined in module A and consumed in module B, the taint engine relies on the interprocedural call graph to connect them rather than `import`/`require` resolution.

- **Framework coverage is not exhaustive.** While Express, Fastify, Hapi, Nest.js, and Next.js are covered, other frameworks (Koa, Adonis, Meteor, Remix loaders, tRPC inputs) have limited or no dedicated source patterns.

- **Dynamic property access.** Patterns like `req.query[varName]` or computed property keys are not tracked as sources. Only static property access patterns (e.g., `req.query.foo`, `req.body`) are recognized.

- **Client-side framework coverage.** React `dangerouslySetInnerHTML` and basic DOM sinks are covered, but Vue.js `v-html`, Angular `bypassSecurityTrust*`, Svelte `{@html}`, and similar framework-specific patterns are not tracked.

- **Prototype chain and closures.** The taint engine does not model JavaScript prototype chains, closures capturing tainted variables, or `this` binding. Taint may be lost when data flows through these mechanisms.

- **Decorator-based routing.** While Nest.js `@Query()`, `@Param()`, `@Body()`, and `@Headers()` decorators are recognized as sources, other decorator-based frameworks may not be covered.

- **Test file exclusion.** Files detected as test files (matching common test path patterns) are excluded from scanning to reduce false positives. This is intentional but means vulnerabilities in test fixtures are not flagged.

- **Async/await and Promise chains.** Taint propagation through `.then()` chains, `async`/`await`, and callback pyramids works at the pattern level but may miss complex asynchronous data flows spanning many functions.

- **Memory rules (GTSS-MEM-*) do not apply.** The memory safety category (buffer overflow, banned functions, etc.) targets C/C++ only and does not apply to JavaScript/TypeScript.
