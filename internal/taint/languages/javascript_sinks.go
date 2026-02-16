package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// jsSinks defines taint sinks for JavaScript/TypeScript.
var jsSinks = []taint.SinkDef{
	// SQL injection
	{ID: "js.sql.query", Category: taint.SnkSQLQuery, Pattern: `\.query\s*\(`, ObjectType: "", MethodName: "query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL query with potential injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.sql.execute", Category: taint.SnkSQLQuery, Pattern: `\.execute\s*\(`, ObjectType: "", MethodName: "execute", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL execute with potential injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.knex.raw", Category: taint.SnkSQLQuery, Pattern: `knex\.raw\s*\(`, ObjectType: "knex", MethodName: "raw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Knex raw SQL query", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.sequelize.query", Category: taint.SnkSQLQuery, Pattern: `sequelize\.query\s*\(`, ObjectType: "sequelize", MethodName: "query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Sequelize raw SQL query", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

	// Command injection
	{ID: "js.child_process.exec", Category: taint.SnkCommand, Pattern: `child_process\.exec\s*\(`, ObjectType: "child_process", MethodName: "exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via child_process.exec", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.child_process.execsync", Category: taint.SnkCommand, Pattern: `child_process\.execSync\s*\(`, ObjectType: "child_process", MethodName: "execSync", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Synchronous OS command execution", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.child_process.spawn", Category: taint.SnkCommand, Pattern: `child_process\.spawn\s*\(`, ObjectType: "child_process", MethodName: "spawn", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command spawn", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.exec.short", Category: taint.SnkCommand, Pattern: `\bexec\s*\(`, ObjectType: "", MethodName: "exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via exec()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.execsync.short", Category: taint.SnkCommand, Pattern: `\bexecSync\s*\(`, ObjectType: "", MethodName: "execSync", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Synchronous OS command execution via execSync()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.spawn.short", Category: taint.SnkCommand, Pattern: `\bspawn\s*\(`, ObjectType: "", MethodName: "spawn", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command spawn via spawn()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

	// Code evaluation
	{ID: "js.eval", Category: taint.SnkEval, Pattern: `\beval\s*\(`, ObjectType: "", MethodName: "eval", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Dynamic code evaluation via eval()", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.new.function", Category: taint.SnkEval, Pattern: `new\s+Function\s*\(`, ObjectType: "", MethodName: "Function", DangerousArgs: []int{-1}, Severity: rules.Critical, Description: "Dynamic function construction", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.settimeout.string", Category: taint.SnkEval, Pattern: `setTimeout\s*\(\s*["'\x60]`, ObjectType: "", MethodName: "setTimeout", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "setTimeout with string argument (implicit eval)", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.setinterval.string", Category: taint.SnkEval, Pattern: `setInterval\s*\(\s*["'\x60]`, ObjectType: "", MethodName: "setInterval", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "setInterval with string argument (implicit eval)", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

	// XSS
	{ID: "js.dom.innerhtml.write", Category: taint.SnkHTMLOutput, Pattern: `\.innerHTML\s*=`, ObjectType: "HTMLElement", MethodName: "innerHTML", DangerousArgs: []int{0}, Severity: rules.High, Description: "innerHTML assignment (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.dom.document.write", Category: taint.SnkHTMLOutput, Pattern: `document\.write\s*\(`, ObjectType: "document", MethodName: "write", DangerousArgs: []int{0}, Severity: rules.High, Description: "document.write (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.react.dangerouslysetinnerhtml", Category: taint.SnkHTMLOutput, Pattern: `dangerouslySetInnerHTML`, ObjectType: "", MethodName: "dangerouslySetInnerHTML", DangerousArgs: []int{0}, Severity: rules.High, Description: "React dangerouslySetInnerHTML (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.express.res.send", Category: taint.SnkHTMLOutput, Pattern: `res\.send\s*\(`, ObjectType: "Response", MethodName: "send", DangerousArgs: []int{0}, Severity: rules.High, Description: "Express response send (potential XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.express.res.write", Category: taint.SnkHTMLOutput, Pattern: `res\.write\s*\(`, ObjectType: "Response", MethodName: "write", DangerousArgs: []int{0}, Severity: rules.High, Description: "Express response write (potential XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

	// Express response sinks
	{ID: "js.express.res.render", Category: taint.SnkEval, Pattern: `res\.render\s*\(`, ObjectType: "Response", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.High, Description: "Express template path injection via res.render", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.express.res.sendfile", Category: taint.SnkFileWrite, Pattern: `res\.sendFile\s*\(`, ObjectType: "Response", MethodName: "sendFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "Path traversal via res.sendFile", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.express.res.download", Category: taint.SnkFileWrite, Pattern: `res\.download\s*\(`, ObjectType: "Response", MethodName: "download", DangerousArgs: []int{0}, Severity: rules.High, Description: "Path traversal via res.download", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// File operations
	{ID: "js.fs.writefile", Category: taint.SnkFileWrite, Pattern: `fs\.writeFile\s*\(`, ObjectType: "fs", MethodName: "writeFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "File write with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.readfile.sink", Category: taint.SnkFileWrite, Pattern: `fs\.readFile\s*\(`, ObjectType: "fs", MethodName: "readFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "File read with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.unlink", Category: taint.SnkFileWrite, Pattern: `fs\.unlink\s*\(`, ObjectType: "fs", MethodName: "unlink", DangerousArgs: []int{0}, Severity: rules.High, Description: "File deletion with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.createreadstream", Category: taint.SnkFileWrite, Pattern: `fs\.createReadStream\s*\(`, ObjectType: "fs", MethodName: "createReadStream", DangerousArgs: []int{0}, Severity: rules.High, Description: "File stream with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// Redirect
	{ID: "js.express.res.redirect", Category: taint.SnkRedirect, Pattern: `res\.redirect\s*\(`, ObjectType: "Response", MethodName: "redirect", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via res.redirect", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.dom.window.location.assign", Category: taint.SnkRedirect, Pattern: `window\.location\s*=`, ObjectType: "window", MethodName: "location", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via window.location assignment", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.dom.location.href.assign", Category: taint.SnkRedirect, Pattern: `location\.href\s*=`, ObjectType: "location", MethodName: "href", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via location.href assignment", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},

	// SSRF
	{ID: "js.fetch.ssrf", Category: taint.SnkURLFetch, Pattern: `fetch\s*\(`, ObjectType: "", MethodName: "fetch", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via fetch", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.axios.get.ssrf", Category: taint.SnkURLFetch, Pattern: `axios\.get\s*\(`, ObjectType: "axios", MethodName: "get", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via axios.get", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.http.get.ssrf", Category: taint.SnkURLFetch, Pattern: `http\.get\s*\(`, ObjectType: "http", MethodName: "get", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via http.get", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.request.ssrf", Category: taint.SnkURLFetch, Pattern: `\brequest\s*\(`, ObjectType: "", MethodName: "request", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via request()", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

	// Deserialization
	{ID: "js.json.parse", Category: taint.SnkDeserialize, Pattern: `JSON\.parse\s*\(`, ObjectType: "JSON", MethodName: "parse", DangerousArgs: []int{0}, Severity: rules.Low, Description: "JSON.parse (low risk deserialization)", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "js.node.serialize", Category: taint.SnkDeserialize, Pattern: `(?:unserialize|deserialize)\s*\(`, ObjectType: "", MethodName: "deserialize", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Unsafe deserialization via node-serialize", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "js.yaml.load", Category: taint.SnkDeserialize, Pattern: `yaml\.load\s*\(`, ObjectType: "yaml", MethodName: "load", DangerousArgs: []int{0}, Severity: rules.High, Description: "Unsafe YAML deserialization via js-yaml.load", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

	// Template injection
	{ID: "js.ejs.render", Category: taint.SnkTemplate, Pattern: `ejs\.render\s*\(`, ObjectType: "ejs", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.High, Description: "EJS template injection", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.pug.render", Category: taint.SnkTemplate, Pattern: `pug\.render\s*\(`, ObjectType: "pug", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.High, Description: "Pug template injection", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.handlebars.compile", Category: taint.SnkTemplate, Pattern: `Handlebars\.compile\s*\(`, ObjectType: "Handlebars", MethodName: "compile", DangerousArgs: []int{0}, Severity: rules.High, Description: "Handlebars template injection", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},

	// Header injection
	{ID: "js.express.res.setheader", Category: taint.SnkHeader, Pattern: `res\.setHeader\s*\(`, ObjectType: "Response", MethodName: "setHeader", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "HTTP header injection via res.setHeader", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.express.res.header", Category: taint.SnkHeader, Pattern: `res\.header\s*\(`, ObjectType: "Response", MethodName: "header", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "HTTP header injection via res.header", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},

	// Prisma raw SQL
	{ID: "js.prisma.queryraw", Category: taint.SnkSQLQuery, Pattern: `\$queryRaw\s*\(`, ObjectType: "PrismaClient", MethodName: "$queryRaw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Prisma raw SQL query (bypasses parameterization)", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.prisma.executeraw", Category: taint.SnkSQLQuery, Pattern: `\$executeRaw\s*\(`, ObjectType: "PrismaClient", MethodName: "$executeRaw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Prisma raw SQL execute (bypasses parameterization)", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.prisma.queryrawunsafe", Category: taint.SnkSQLQuery, Pattern: `\$queryRawUnsafe\s*\(`, ObjectType: "PrismaClient", MethodName: "$queryRawUnsafe", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Prisma unsafe raw query with string interpolation", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.prisma.executerawunsafe", Category: taint.SnkSQLQuery, Pattern: `\$executeRawUnsafe\s*\(`, ObjectType: "PrismaClient", MethodName: "$executeRawUnsafe", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Prisma unsafe raw execute with string interpolation", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

	// Mongoose/MongoDB injection
	{ID: "js.mongoose.where", Category: taint.SnkSQLQuery, Pattern: `\.\$where\s*\(`, ObjectType: "MongooseQuery", MethodName: "$where", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "MongoDB $where operator (JS code execution)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.where.concat", Category: taint.SnkSQLQuery, Pattern: `\$where\s*:\s*['"][^'"]*['"]\s*\+`, ObjectType: "MongooseQuery", MethodName: "$where (concat)", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "MongoDB $where with string concatenation (NoSQL code injection)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.where.template", Category: taint.SnkSQLQuery, Pattern: `\$where\s*:\s*` + "`[^`]*\\$\\{", ObjectType: "MongooseQuery", MethodName: "$where (template)", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "MongoDB $where with template literal interpolation (NoSQL code injection)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.find.tainted", Category: taint.SnkSQLQuery, Pattern: `\.find\s*\(`, ObjectType: "MongooseModel", MethodName: "find", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB find with user-controlled query object", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.aggregate.tainted", Category: taint.SnkSQLQuery, Pattern: `\.aggregate\s*\(`, ObjectType: "MongooseModel", MethodName: "aggregate", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB aggregate pipeline with tainted data", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.findone", Category: taint.SnkSQLQuery, Pattern: `\.findOne\s*\(`, ObjectType: "MongooseModel", MethodName: "findOne", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB findOne with user-controlled query", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.update", Category: taint.SnkSQLQuery, Pattern: `\.update\s*\(`, ObjectType: "MongooseModel", MethodName: "update", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB update with tainted query/data", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.updateone", Category: taint.SnkSQLQuery, Pattern: `\.updateOne\s*\(`, ObjectType: "MongooseModel", MethodName: "updateOne", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB updateOne with tainted query/data", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.updatemany", Category: taint.SnkSQLQuery, Pattern: `\.updateMany\s*\(`, ObjectType: "MongooseModel", MethodName: "updateMany", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB updateMany with tainted query/data", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.deleteone", Category: taint.SnkSQLQuery, Pattern: `\.deleteOne\s*\(`, ObjectType: "MongooseModel", MethodName: "deleteOne", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB deleteOne with tainted query", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.deletemany", Category: taint.SnkSQLQuery, Pattern: `\.deleteMany\s*\(`, ObjectType: "MongooseModel", MethodName: "deleteMany", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB deleteMany with tainted query", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.findoneandupdate", Category: taint.SnkSQLQuery, Pattern: `\.findOneAndUpdate\s*\(`, ObjectType: "MongooseModel", MethodName: "findOneAndUpdate", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB findOneAndUpdate with tainted query/data", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.findoneanddelete", Category: taint.SnkSQLQuery, Pattern: `\.findOneAndDelete\s*\(`, ObjectType: "MongooseModel", MethodName: "findOneAndDelete", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB findOneAndDelete with tainted query", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.insertone", Category: taint.SnkSQLQuery, Pattern: `\.insertOne\s*\(`, ObjectType: "MongooseModel", MethodName: "insertOne", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB insertOne with tainted data", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.insertmany", Category: taint.SnkSQLQuery, Pattern: `\.insertMany\s*\(`, ObjectType: "MongooseModel", MethodName: "insertMany", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB insertMany with tainted data", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.replaceone", Category: taint.SnkSQLQuery, Pattern: `\.replaceOne\s*\(`, ObjectType: "MongooseModel", MethodName: "replaceOne", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB replaceOne with tainted data", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},

	// child_process additional sinks
	{ID: "js.child_process.execfile", Category: taint.SnkCommand, Pattern: `(?:child_process\.)?execFile\s*\(`, ObjectType: "child_process", MethodName: "execFile", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via execFile", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.child_process.fork", Category: taint.SnkCommand, Pattern: `(?:child_process\.)?fork\s*\(`, ObjectType: "child_process", MethodName: "fork", DangerousArgs: []int{0}, Severity: rules.High, Description: "Node child process fork with tainted module path", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

	// vm module (code eval)
	{ID: "js.vm.runincontext", Category: taint.SnkEval, Pattern: `vm\.runInContext\s*\(`, ObjectType: "vm", MethodName: "runInContext", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Code execution via vm.runInContext", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.vm.runinnewcontext", Category: taint.SnkEval, Pattern: `vm\.runInNewContext\s*\(`, ObjectType: "vm", MethodName: "runInNewContext", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Code execution via vm.runInNewContext", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.vm.runinthiscontext", Category: taint.SnkEval, Pattern: `vm\.runInThisContext\s*\(`, ObjectType: "vm", MethodName: "runInThisContext", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Code execution via vm.runInThisContext", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.vm.script", Category: taint.SnkEval, Pattern: `new\s+vm\.Script\s*\(`, ObjectType: "vm", MethodName: "Script", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Code compilation via new vm.Script", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

	// Crypto weak patterns
	{ID: "js.crypto.createhash.md5", Category: taint.SnkCrypto, Pattern: `createHash\s*\(\s*['"]md5['"]`, ObjectType: "crypto", MethodName: "createHash", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Weak hash algorithm (MD5)", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},
	{ID: "js.crypto.createhash.sha1", Category: taint.SnkCrypto, Pattern: `createHash\s*\(\s*['"]sha1['"]`, ObjectType: "crypto", MethodName: "createHash", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Weak hash algorithm (SHA-1)", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},
	{ID: "js.crypto.createcipheriv.weak", Category: taint.SnkCrypto, Pattern: `createCipheriv\s*\(\s*['"](?:des|rc4|aes-128-ecb)['"]`, ObjectType: "crypto", MethodName: "createCipheriv", DangerousArgs: []int{0}, Severity: rules.High, Description: "Weak cipher algorithm (DES/RC4/ECB mode)", CWEID: "CWE-327", OWASPCategory: "A02:2021-Cryptographic Failures"},

	// Insecure random
	{ID: "js.crypto.math_random", Category: taint.SnkCrypto, Pattern: `Math\.random\s*\(`, ObjectType: "Math", MethodName: "random", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Math.random() used for security-sensitive value (use crypto.randomBytes instead)", CWEID: "CWE-338", OWASPCategory: "A02:2021-Cryptographic Failures"},

	// JWT without verification
	{ID: "js.jwt.decode.noverify", Category: taint.SnkCrypto, Pattern: `jwt\.decode\s*\(|jsonwebtoken\.decode\s*\(`, ObjectType: "jsonwebtoken", MethodName: "decode", DangerousArgs: []int{0}, Severity: rules.High, Description: "JWT decoded without signature verification (use jwt.verify instead)", CWEID: "CWE-345", OWASPCategory: "A02:2021-Cryptographic Failures"},
	{ID: "js.jwt.verify.none_algo", Category: taint.SnkCrypto, Pattern: `jwt\.verify\s*\(.*algorithms\s*:\s*\[.*['"]none['"]`, ObjectType: "jsonwebtoken", MethodName: "verify (none)", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "JWT verification with 'none' algorithm allowed", CWEID: "CWE-345", OWASPCategory: "A02:2021-Cryptographic Failures"},

	// Redis command injection
	{ID: "js.redis.sendcommand", Category: taint.SnkCommand, Pattern: `\.sendCommand\s*\(`, ObjectType: "RedisClient", MethodName: "sendCommand", DangerousArgs: []int{0}, Severity: rules.High, Description: "Redis command execution with tainted arguments", CWEID: "CWE-77", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.redis.eval", Category: taint.SnkEval, Pattern: `\.eval\s*\(`, ObjectType: "RedisClient", MethodName: "eval", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Redis Lua script evaluation with tainted script", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

	// DNS lookup with tainted hostname
	{ID: "js.dns.lookup", Category: taint.SnkURLFetch, Pattern: `dns\.lookup\s*\(|dns\.resolve\s*\(`, ObjectType: "dns", MethodName: "lookup/resolve", DangerousArgs: []int{0}, Severity: rules.High, Description: "DNS lookup with tainted hostname (SSRF/DNS rebinding)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

	// Docker exec
	{ID: "js.dockerode.exec", Category: taint.SnkCommand, Pattern: `container\.exec\s*\(`, ObjectType: "Dockerode.Container", MethodName: "exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Docker container exec with tainted command", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

	// Kafka message construction
	{ID: "js.kafkajs.send", Category: taint.SnkCommand, Pattern: `producer\.send\s*\(`, ObjectType: "KafkaJS.Producer", MethodName: "send", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Kafka message produced with tainted data", CWEID: "CWE-77", OWASPCategory: "A03:2021-Injection"},

	// SMTP/email header injection
	{ID: "js.nodemailer.sendmail", Category: taint.SnkHeader, Pattern: `transporter\.sendMail\s*\(|\.sendMail\s*\(`, ObjectType: "Nodemailer", MethodName: "sendMail", DangerousArgs: []int{0}, Severity: rules.High, Description: "Email send with tainted headers/recipients (email injection)", CWEID: "CWE-93", OWASPCategory: "A03:2021-Injection"},

	// Log injection (CWE-117)
	{ID: "js.console.log", Category: taint.SnkLog, Pattern: `console\.log\s*\(`, ObjectType: "console", MethodName: "log", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "console.log with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
	{ID: "js.console.warn", Category: taint.SnkLog, Pattern: `console\.warn\s*\(`, ObjectType: "console", MethodName: "warn", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "console.warn with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
	{ID: "js.console.error", Category: taint.SnkLog, Pattern: `console\.error\s*\(`, ObjectType: "console", MethodName: "error", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "console.error with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
	{ID: "js.console.info", Category: taint.SnkLog, Pattern: `console\.info\s*\(`, ObjectType: "console", MethodName: "info", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "console.info with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
	{ID: "js.winston.log", Category: taint.SnkLog, Pattern: `winston\.(?:log|info|warn|error|debug)\s*\(`, ObjectType: "winston", MethodName: "log", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Winston logger with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
	{ID: "js.pino.log", Category: taint.SnkLog, Pattern: `pino\.(?:info|warn|error|debug|fatal|trace)\s*\(`, ObjectType: "pino", MethodName: "log", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Pino logger with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
	{ID: "js.bunyan.log", Category: taint.SnkLog, Pattern: `bunyan\.(?:info|warn|error|debug|fatal|trace)\s*\(`, ObjectType: "bunyan", MethodName: "log", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Bunyan logger with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
	{ID: "js.logger.generic", Category: taint.SnkLog, Pattern: `logger\.(?:info|warn|error|debug|log)\s*\(`, ObjectType: "Logger", MethodName: "log", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Logger with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},

	// Additional file operations
	{ID: "js.fs.writefilesync", Category: taint.SnkFileWrite, Pattern: `fs\.writeFileSync\s*\(`, ObjectType: "fs", MethodName: "writeFileSync", DangerousArgs: []int{0}, Severity: rules.High, Description: "Synchronous file write with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.mkdir", Category: taint.SnkFileWrite, Pattern: `fs\.mkdir\s*\(|fs\.mkdirSync\s*\(`, ObjectType: "fs", MethodName: "mkdir/mkdirSync", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Directory creation with potentially tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.rename", Category: taint.SnkFileWrite, Pattern: `fs\.rename\s*\(|fs\.renameSync\s*\(`, ObjectType: "fs", MethodName: "rename/renameSync", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "File rename with potentially tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.symlink", Category: taint.SnkFileWrite, Pattern: `fs\.symlink\s*\(|fs\.symlinkSync\s*\(`, ObjectType: "fs", MethodName: "symlink/symlinkSync", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "Symlink creation with potentially tainted path", CWEID: "CWE-59", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.copyfile", Category: taint.SnkFileWrite, Pattern: `fs\.copyFile\s*\(|fs\.copyFileSync\s*\(`, ObjectType: "fs", MethodName: "copyFile/copyFileSync", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "File copy with potentially tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// XSS additional vectors
	{ID: "js.dom.outerhtml", Category: taint.SnkHTMLOutput, Pattern: `\.outerHTML\s*=`, ObjectType: "HTMLElement", MethodName: "outerHTML", DangerousArgs: []int{0}, Severity: rules.High, Description: "outerHTML assignment (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.dom.insertadjacenthtml", Category: taint.SnkHTMLOutput, Pattern: `\.insertAdjacentHTML\s*\(`, ObjectType: "HTMLElement", MethodName: "insertAdjacentHTML", DangerousArgs: []int{1}, Severity: rules.High, Description: "insertAdjacentHTML (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.dom.document.writeln", Category: taint.SnkHTMLOutput, Pattern: `document\.writeln\s*\(`, ObjectType: "document", MethodName: "writeln", DangerousArgs: []int{0}, Severity: rules.High, Description: "document.writeln (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

	// ReDoS
	{ID: "js.regexp.constructor", Category: taint.SnkEval, Pattern: `new\s+RegExp\s*\(`, ObjectType: "", MethodName: "RegExp", DangerousArgs: []int{0}, Severity: rules.High, Description: "RegExp construction with potentially tainted pattern (ReDoS)", CWEID: "CWE-1333", OWASPCategory: "A03:2021-Injection"},

	// Additional SSRF vectors
	{ID: "js.axios.post.ssrf", Category: taint.SnkURLFetch, Pattern: `axios\.post\s*\(|axios\.put\s*\(|axios\.delete\s*\(|axios\.patch\s*\(`, ObjectType: "axios", MethodName: "post/put/delete/patch", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via axios HTTP methods", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.got.ssrf", Category: taint.SnkURLFetch, Pattern: `got\s*\(|got\.get\s*\(|got\.post\s*\(`, ObjectType: "got", MethodName: "got", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via got HTTP client", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.node-fetch.ssrf", Category: taint.SnkURLFetch, Pattern: `node-fetch|import.*fetch|require.*node-fetch`, ObjectType: "node-fetch", MethodName: "fetch", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via node-fetch", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

	// Deprecated crypto
	{ID: "js.crypto.createcipher", Category: taint.SnkCrypto, Pattern: `crypto\.createCipher\s*\(`, ObjectType: "crypto", MethodName: "createCipher", DangerousArgs: []int{0}, Severity: rules.High, Description: "Deprecated crypto.createCipher without IV (use createCipheriv)", CWEID: "CWE-327", OWASPCategory: "A02:2021-Cryptographic Failures"},
}
