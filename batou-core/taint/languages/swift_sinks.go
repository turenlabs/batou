package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (c *SwiftCatalog) Sinks() []taint.SinkDef {
	return []taint.SinkDef{
		// --- File Operations (CWE-22) ---
		{
			ID:            "swift.filemanager.createfile",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `FileManager\.default\.createFile\(|\.createFile\(\s*atPath:`,
			ObjectType:    "FileManager",
			MethodName:    "createFile(atPath:)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File creation with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.filemanager.contents",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `FileManager\.default\.contents\(\s*atPath:|\.contentsOfDirectory\(`,
			ObjectType:    "FileManager",
			MethodName:    "contents(atPath:)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File read with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.filemanager.movecopy",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `FileManager\.default\.(?:moveItem|copyItem)\(`,
			ObjectType:    "FileManager",
			MethodName:    "moveItem/copyItem",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "File move/copy with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.data.write",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `\.write\(\s*to:\s*URL|\.write\(\s*toFile:`,
			ObjectType:    "Data",
			MethodName:    "write(to:)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Data write to potentially tainted file path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Archive Extraction / Zip Slip (CWE-22) ---
		// Writing archive contents to disk without sanitizing per-entry
		// paths enables Zip Slip: a crafted entry name like
		// `../../etc/passwd` can escape the destination directory.
		// Classic vuln class documented by Snyk (2018).
		{
			ID:            "swift.zipfoundation.archive.extract",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `\.extract\s*\(\s*[A-Za-z_]\w*\s*,\s*to:`,
			ObjectType:    "Archive",
			MethodName:    "extract",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "ZIPFoundation Archive.extract(_:to:) with attacker-controlled destination (Zip Slip)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.zipfoundation.unzipitem",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `\.unzipItem\s*\(\s*at:`,
			ObjectType:    "FileManager",
			MethodName:    "unzipItem",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "FileManager.unzipItem(at:to:) extracts untrusted archive contents (Zip Slip risk if entries not validated)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.sszip.unzipfile",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `SSZipArchive\.unzipFile\s*\(\s*atPath:`,
			ObjectType:    "SSZipArchive",
			MethodName:    "unzipFile",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSZipArchive.unzipFile with attacker-controlled archive path (Zip Slip — CVE-2019-19325 class)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Network / SSRF (CWE-918) ---
		{
			ID:            "swift.urlsession.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `URLSession\.shared\.dataTask\(\s*with:|\.dataTask\(\s*with:\s*URLRequest`,
			ObjectType:    "URLSession",
			MethodName:    "dataTask(with:)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "URL request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- Command Execution (CWE-78) ---
		{
			ID:            "swift.process.launch",
			Category:      taint.SnkCommand,
			Language:      rules.LangSwift,
			Pattern:       `Process\(\)|NSTask\(\)`,
			ObjectType:    "Process",
			MethodName:    "Process/NSTask",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "OS process/command execution with potentially tainted arguments",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.process.arguments",
			Category:      taint.SnkCommand,
			Language:      rules.LangSwift,
			Pattern:       `\.arguments\s*=|\.launchPath\s*=`,
			ObjectType:    "Process",
			MethodName:    "arguments/launchPath",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Process arguments set with potentially tainted values",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- C interop command execution (CWE-78) ---
		{
			ID:            "swift.system",
			Category:      taint.SnkCommand,
			Language:      rules.LangSwift,
			Pattern:       `\bsystem\s*\(`,
			ObjectType:    "",
			MethodName:    "system",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "C interop system() passes string directly to shell for execution",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.popen",
			Category:      taint.SnkCommand,
			Language:      rules.LangSwift,
			Pattern:       `\bpopen\s*\(`,
			ObjectType:    "",
			MethodName:    "popen",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "C interop popen() opens pipe to shell command for execution",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		// --- ShellOut + POSIX spawn/exec command execution (CWE-78) ---
		// Swift already models Process/NSTask, system(), popen() and the
		// modern Process.run() API, but not the widely-used ShellOut package
		// (johnsundell/ShellOut) nor the low-level POSIX process-launch
		// primitives bridged from Glibc/Darwin.
		{
			ID:            "swift.shellout",
			Category:      taint.SnkCommand,
			Language:      rules.LangSwift,
			Pattern:       `shellOut\s*\(\s*to:`,
			ObjectType:    "",
			MethodName:    "shellOut",
			DangerousArgs: []int{0, 1},
			Severity:      rules.Critical,
			Description:   "ShellOut (johnsundell/ShellOut) shellOut(to:) runs its command via /bin/bash -c, joining the `to:` string and any `arguments:` into one shell line — neither is shell-escaped, so tainted data in either is OS command injection (CWE-78). Do not pass user input to ShellOut; use Foundation's Process with executableURL + arguments (no shell), or strictly validate/allowlist the value first.",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.posix.spawn",
			Category:      taint.SnkCommand,
			Language:      rules.LangSwift,
			Pattern:       `\bposix_spawnp?\s*\(`,
			ObjectType:    "",
			MethodName:    "posix_spawn/posix_spawnp",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "POSIX posix_spawn / posix_spawnp launch a new process; arg 1 is the executable path (posix_spawnp additionally resolves it via $PATH). A tainted path lets an attacker run an arbitrary binary (CWE-78). Validate the executable against an allowlist of known-safe absolute paths before spawning.",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.posix.exec",
			Category:      taint.SnkCommand,
			Language:      rules.LangSwift,
			Pattern:       `\bexecv[pe]?\s*\(`,
			ObjectType:    "",
			MethodName:    "execv/execve/execvp",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "POSIX execv/execve/execvp replace the current process image with a new program; arg 0 is the executable path/file (execvp resolves it via $PATH). A tainted path runs an attacker-chosen binary (CWE-78). Validate the executable against an allowlist of known-safe absolute paths before exec.",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		// --- WKWebView JavaScript Injection (CWE-79) ---
		{
			ID:            "swift.wkwebview.evaluatejavascript",
			Category:      taint.SnkEval,
			Language:      rules.LangSwift,
			Pattern:       `\.evaluateJavaScript\(`,
			ObjectType:    "WKWebView",
			MethodName:    "evaluateJavaScript",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "WKWebView JavaScript evaluation with potentially tainted script",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		// --- JavaScriptCore JSContext eval (CWE-95) ---
		// Apple's JavaScriptCore framework (bundled with iOS/macOS) executes
		// JavaScript via JSContext.evaluateScript. Bridged native objects
		// (JSExport, setObject) make this RCE-equivalent if the script is
		// attacker-controlled. See Apple sample plugin systems.
		{
			ID:            "swift.jscontext.evaluatescript",
			Category:      taint.SnkEval,
			Language:      rules.LangSwift,
			Pattern:       `\.evaluateScript\s*\(`,
			ObjectType:    "",
			MethodName:    "evaluateScript",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "JavaScriptCore JSContext.evaluateScript with potentially tainted script (RCE via bridged native objects)",
			CWEID:         "CWE-95",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.jsvalue.invokemethod",
			Category:      taint.SnkEval,
			Language:      rules.LangSwift,
			Pattern:       `\.invokeMethod\s*\(\s*[^,)]+,\s*withArguments:`,
			ObjectType:    "",
			MethodName:    "invokeMethod",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "JavaScriptCore JSValue.invokeMethod with tainted method name allows arbitrary JS function invocation",
			CWEID:         "CWE-95",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.wkwebview.loadhtmlstring",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangSwift,
			Pattern:       `\.loadHTMLString\(`,
			ObjectType:    "WKWebView",
			MethodName:    "loadHTMLString",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "WKWebView HTML loading with potentially tainted content",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- SQLite Injection (CWE-89) ---
		{
			ID:            "swift.sqlite3.exec",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `sqlite3_exec\(`,
			ObjectType:    "",
			MethodName:    "sqlite3_exec",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "SQLite query execution with potentially tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.sqlite3.prepare",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `sqlite3_prepare(?:_v[23])?\(`,
			ObjectType:    "",
			MethodName:    "sqlite3_prepare",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "SQLite prepare with potentially tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- SQLite.swift (stephencelis) raw-SQL sinks (CWE-89) ---
		// SQLite.swift Connection exposes run/prepare/execute/scalar that accept
		// a raw SQL string as arg 0. Parameter bindings (arg 1+) are safe; taint
		// reaching the SQL string itself is an injection. Receiver is typically
		// `db`, `database`, `conn`, or `connection` — matched via the Connection
		// receiver heuristic in tsflow/matcher.go.
		{
			ID:            "swift.sqliteswift.run",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `(?:db|database|conn|connection)\.run\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "run",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQLite.swift Connection.run with potentially tainted SQL string (CWE-89)",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.sqliteswift.prepare",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `(?:db|database|conn|connection)\.prepare\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "prepare",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SQLite.swift Connection.prepare with potentially tainted SQL string (CWE-89)",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.sqliteswift.execute",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `(?:db|database|conn|connection)\.execute\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "execute",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQLite.swift Connection.execute with potentially tainted SQL batch (CWE-89)",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.sqliteswift.scalar",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `(?:db|database|conn|connection)\.scalar\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "scalar",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SQLite.swift Connection.scalar with potentially tainted SQL string (CWE-89)",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Insecure Storage (CWE-922) ---
		// NOTE: the `UserDefaults.standard.set(_:forKey:)` storage call is
		// modelled by `swift.trust.userdefaults.set` (SnkTrustBoundary, CWE-501)
		// further down. A second entry here keyed under the argument-label form
		// `set(_:forKey:)` was previously inert (the tsflow matcher mangled the
		// `(label:)` key to `)`), so removing it changes no prior behaviour;
		// keeping it would shadow the more specific trust-boundary
		// classification now that the arg-label keying is fixed.

		// --- Keychain with insecure access (CWE-921) ---
		{
			ID:            "swift.keychain.accessible.always",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `kSecAttrAccessibleAlways\b|kSecAttrAccessibleAlwaysThisDeviceOnly\b`,
			ObjectType:    "Security",
			MethodName:    "kSecAttrAccessibleAlways",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Keychain item accessible when device is locked",
			CWEID:         "CWE-921",
			OWASPCategory: "A04:2021-Insecure Design",
		},

		// --- Logging sensitive data (CWE-532) ---
		{
			ID:            "swift.oslog",
			Category:      taint.SnkLog,
			Language:      rules.LangSwift,
			Pattern:       `os_log\(|Logger\(\)\.(?:info|debug|error|warning|notice|critical|fault)\(`,
			ObjectType:    "",
			MethodName:    "os_log/Logger",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Logging with potentially sensitive tainted data",
			CWEID:         "CWE-532",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "swift.nslog",
			Category:      taint.SnkLog,
			Language:      rules.LangSwift,
			Pattern:       `NSLog\(`,
			ObjectType:    "",
			MethodName:    "NSLog",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "NSLog with potentially sensitive tainted data",
			CWEID:         "CWE-532",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "swift.print.sensitive",
			Category:      taint.SnkLog,
			Language:      rules.LangSwift,
			Pattern:       `print\(`,
			ObjectType:    "",
			MethodName:    "print",
			DangerousArgs: []int{0},
			Severity:      rules.Low,
			Description:   "Print statement with potentially sensitive data",
			CWEID:         "CWE-532",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},

		// --- stdlib logging (CWE-532) ---
		{
			ID:            "swift.debugprint",
			Category:      taint.SnkLog,
			Language:      rules.LangSwift,
			Pattern:       `debugPrint\s*\(`,
			ObjectType:    "",
			MethodName:    "debugPrint",
			DangerousArgs: []int{0},
			Severity:      rules.Low,
			Description:   "debugPrint with potentially sensitive data (detailed output)",
			CWEID:         "CWE-532",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "swift.dump",
			Category:      taint.SnkLog,
			Language:      rules.LangSwift,
			Pattern:       `\bdump\s*\(`,
			ObjectType:    "",
			MethodName:    "dump",
			DangerousArgs: []int{0},
			Severity:      rules.Low,
			Description:   "dump() outputs detailed object representation with potentially sensitive data",
			CWEID:         "CWE-532",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},

		// --- CocoaLumberjack Swift wrappers — log injection (CWE-117) ---
		{
			ID:            "swift.cocoalumberjack.ddlogerror",
			Category:      taint.SnkLog,
			Language:      rules.LangSwift,
			Pattern:       `\bDDLogError\s*\(`,
			ObjectType:    "",
			MethodName:    "DDLogError",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "CocoaLumberjack DDLogError with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "swift.cocoalumberjack.ddlogwarn",
			Category:      taint.SnkLog,
			Language:      rules.LangSwift,
			Pattern:       `\bDDLogWarn\s*\(`,
			ObjectType:    "",
			MethodName:    "DDLogWarn",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "CocoaLumberjack DDLogWarn with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "swift.cocoalumberjack.ddloginfo",
			Category:      taint.SnkLog,
			Language:      rules.LangSwift,
			Pattern:       `\bDDLogInfo\s*\(`,
			ObjectType:    "",
			MethodName:    "DDLogInfo",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "CocoaLumberjack DDLogInfo with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "swift.cocoalumberjack.ddlogdebug",
			Category:      taint.SnkLog,
			Language:      rules.LangSwift,
			Pattern:       `\bDDLogDebug\s*\(`,
			ObjectType:    "",
			MethodName:    "DDLogDebug",
			DangerousArgs: []int{0},
			Severity:      rules.Low,
			Description:   "CocoaLumberjack DDLogDebug with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "swift.cocoalumberjack.ddlogverbose",
			Category:      taint.SnkLog,
			Language:      rules.LangSwift,
			Pattern:       `\bDDLogVerbose\s*\(`,
			ObjectType:    "",
			MethodName:    "DDLogVerbose",
			DangerousArgs: []int{0},
			Severity:      rules.Low,
			Description:   "CocoaLumberjack DDLogVerbose with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},

		// --- Pasteboard write (CWE-200) ---
		{
			ID:            "swift.pasteboard.write",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangSwift,
			Pattern:       `UIPasteboard\.general\.string\s*=|UIPasteboard\.general\.setValue\(`,
			ObjectType:    "UIPasteboard",
			MethodName:    "string= / setValue",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Sensitive data written to system pasteboard",
			CWEID:         "CWE-200",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Vapor response (CWE-79) ---
		//
		// Returning attacker-controlled data inside an HTML response body is the
		// canonical Vapor reflected-XSS vector — the parity equivalent of Java
		// `response.getWriter().println(name)` (BATOU-XSS-029, fires CWE-79 at
		// dataflow tier). The idiomatic constructor form
		//     return Response(status: .ok, body: .init(string: "<h1>\(name)</h1>"))
		// builds a `Response` directly from an interpolated/concatenated string.
		//
		// The prior single entry was DEAD at the dataflow tier: its MethodName
		// `Response(body:)` carried a parenthetical qualifier, which
		// extractMethodNames mangles to the unreachable key `)` (tsflow keys the
		// constructor call `Response(...)` on the bare type name `Response`). So
		// the shape only reached the Layer-1 regex tier (BATOU-SWIFT-020, conf
		// 0.5, non-blocking). Re-key to a wildcard ObjectType + bare MethodName
		// `Response` (the matcher's constructor branch bridges receiver=="" via
		// `unqualify(callName)==unqualify(ObjectType)`), keep the tight
		// constructor-anchored Pattern, and flag ALL args (-1) so the tainted
		// `body:` content fires regardless of whether a `status:` arg precedes it
		// (the `status:` arg is always an enum literal `.ok`/`.badRequest`, never
		// tainted, so it cannot cause a false positive). The `.text(...)`/
		// `.string(...)` HTML-escaping helpers are NOT a Vapor concept; Leaf
		// (`req.view.render`) is the safe templating path and is modelled
		// separately — a raw interpolated Response body is unescaped by design.
		{
			ID:            "swift.vapor.response.body",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangSwift,
			Pattern:       `\bResponse\s*\([^)]*body:\s*\.(?:init\(\s*string:|string\()`,
			ObjectType:    "",
			MethodName:    "Response",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Vapor HTTP response constructed with a potentially tainted HTML string body (reflected XSS - CWE-79). Return rendered Leaf templates (req.view.render) which auto-escape, or HTML-escape interpolated user input before building a raw Response string body. Only a raw `body: .init(string:)` HTML body fires; a serialized JSON/Data body (`body: .init(data:)`) is not an HTML-injection vector and is excluded.",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		// Vapor `encodeResponse(for:)` / Content `.encodeResponse(` — the
		// Content-protocol response-encoding path. A method call on a model/value
		// receiver, keyed on the bare method name `encodeResponse`.
		{
			ID:            "swift.vapor.encoderesponse",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangSwift,
			Pattern:       `\.encodeResponse\s*\(`,
			ObjectType:    "",
			MethodName:    "encodeResponse",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Vapor encodeResponse(for:) with potentially tainted data (reflected XSS — CWE-79)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Template Injection (CWE-1336) ---
		{
			ID:            "swift.leaf.render",
			Category:      taint.SnkTemplate,
			Language:      rules.LangSwift,
			Pattern:       `req\.view\.render\s*\(|app\.view\.render\s*\(`,
			ObjectType:    "ViewRenderer",
			MethodName:    "view.render",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Vapor Leaf template rendering with potentially tainted data",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.stencil.render",
			Category:      taint.SnkTemplate,
			Language:      rules.LangSwift,
			Pattern:       `Environment\(\)\.renderTemplate\s*\(|Template\(.*\)\.render\s*\(`,
			ObjectType:    "Stencil",
			MethodName:    "renderTemplate/render",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Stencil template rendering with potentially tainted context",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Mustache template injection (CWE-1336) ---
		{
			ID:            "swift.mustache.render",
			Category:      taint.SnkTemplate,
			Language:      rules.LangSwift,
			Pattern:       `MustacheTemplate\s*\(.*\)\.render\s*\(`,
			ObjectType:    "",
			MethodName:    "MustacheTemplate.render",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HummingbirdMustache template rendering with potentially tainted context",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- GRDB / FMDB SQL (CWE-89) ---
		{
			ID:            "swift.grdb.execute",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `db\.execute\(\s*sql:|\.execute\(\s*sql:`,
			ObjectType:    "GRDB",
			MethodName:    "execute(sql:)",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "GRDB SQL execution with potentially tainted query",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.fmdb.executequery",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `\.executeQuery\s*\(|\.executeUpdate\s*\(`,
			ObjectType:    "FMDatabase",
			MethodName:    "executeQuery/executeUpdate",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "FMDB SQL execution with potentially tainted query",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- GRDB raw-SQL fetching & statement preparation (CWE-89) ---
		//
		// GRDB's row/value/record fetch methods accept a *raw SQL string* under
		// the `sql:` label as the SECOND positional argument (the first is the
		// `Database` connection, conventionally named `db`):
		//     try Row.fetchAll(db, sql: "SELECT ... WHERE name = '\(name)'")
		//     try Player.fetchOne(db, sql: "SELECT ... \(col)")
		// String interpolation / concatenation of user input into that `sql:`
		// string is the canonical GRDB SQL-injection vector (the GRDB README's
		// "Avoiding SQL Injection" section flags exactly this shape). The safe
		// form keeps `sql:` a constant with `?` placeholders and passes the
		// user value via `arguments:` (a later arg) — there arg 1 is a constant
		// and never tainted, so no flow fires.
		//
		// ObjectType is "" to mirror the existing second-order source
		// `swift.grdb.row.fetch` (same fetchAll/fetchOne/fetchCursor methods)
		// and to also cover typed-record / value fetches (`Player.fetchAll`,
		// `String.fetchOne`). The DangerousArgs index of 1 (not 0) means a
		// bare single-arg `.fetchAll()` cannot fire — only a 2+-arg fetch whose
		// SQL string is tainted — which keeps the wildcard ObjectType from
		// matching unrelated `.fetchAll(x)` calls. `fetchAll`/`fetchOne`/
		// `fetchCursor` are GRDB-specific in the Swift ecosystem (Realm uses
		// `Results`, CoreData uses `fetch(_:)`).
		{
			ID:            "swift.grdb.fetch.sql",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `\.fetch(?:All|One|Cursor)\s*\(\s*\w+\s*,\s*sql:`,
			ObjectType:    "",
			MethodName:    "fetchAll/fetchOne/fetchCursor",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "GRDB raw-SQL fetch with potentially tainted SQL string (CWE-89)",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.grdb.makestatement",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `(?:db|database|conn|connection)\.makeStatement\s*\(\s*sql:`,
			ObjectType:    "Database",
			MethodName:    "makeStatement",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "GRDB Database.makeStatement with potentially tainted SQL string (CWE-89)",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.grdb.cachedstatement",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `(?:db|database|conn|connection)\.cachedStatement\s*\(\s*sql:`,
			ObjectType:    "Database",
			MethodName:    "cachedStatement",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "GRDB Database.cachedStatement with potentially tainted SQL string (CWE-89)",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Weak Crypto (CWE-328) ---
		{
			ID:            "swift.crypto.cc_md5",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `CC_MD5\s*\(|Insecure\.MD5`,
			ObjectType:    "",
			MethodName:    "CC_MD5/Insecure.MD5",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Weak MD5 hash algorithm usage",
			CWEID:         "CWE-328",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "swift.crypto.cc_sha1",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `CC_SHA1\s*\(|Insecure\.SHA1`,
			ObjectType:    "",
			MethodName:    "CC_SHA1/Insecure.SHA1",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Weak SHA1 hash algorithm usage",
			CWEID:         "CWE-328",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// --- CryptoSwift weak hashes (CWE-328) ---
		// CryptoSwift (github.com/krzyzanowskim/CryptoSwift) exposes MD5 and SHA1
		// via both String/Array extensions (`"password".md5()`) and the static
		// Digest API (`Digest.md5(bytes)`). Both produce the same weak digests
		// and are commonly misused for password hashing. Reference:
		// https://cryptoswift.io/  — "Do not use for passwords" guidance.
		{
			ID:            "swift.cryptoswift.md5",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `\.md5\s*\(\s*\)|Digest\.md5\s*\(`,
			ObjectType:    "",
			MethodName:    "md5",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "CryptoSwift MD5 hash (String/Array extension or Digest.md5) — MD5 is cryptographically broken; use SHA-256 or SHA-3 for integrity, and bcrypt/scrypt/Argon2 for passwords",
			CWEID:         "CWE-328",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "swift.cryptoswift.sha1",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `\.sha1\s*\(\s*\)|Digest\.sha1\s*\(`,
			ObjectType:    "",
			MethodName:    "sha1",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "CryptoSwift SHA-1 hash (String/Array extension or Digest.sha1) — SHA-1 is collision-broken (SHAttered, 2017); use SHA-256 or SHA-3 for integrity",
			CWEID:         "CWE-328",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// --- CryptoSwift weak/deprecated block ciphers (CWE-327) ---
		// CryptoSwift ships DES, Blowfish, RC4, and RC2 cipher classes. NIST
		// withdrew DES approval in 2005 (64-bit block, 56-bit key). Blowfish's
		// 64-bit block suffers from Sweet32 birthday attacks (2016). RC4 has
		// been banned for TLS since RFC 7465 (2015). RC2 is export-grade and
		// trivially brute-forceable. The Pattern matches the CryptoSwift
		// constructor form `DES(key: ...)`, etc., to avoid false-positives
		// on unrelated DES/RC4 symbols.
		{
			ID:            "swift.cryptoswift.des",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `\bDES\s*\(\s*key\s*:`,
			ObjectType:    "",
			MethodName:    "DES",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "CryptoSwift DES cipher — DES is cryptographically broken (56-bit key, 64-bit block); use AES-256-GCM instead",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "swift.cryptoswift.blowfish",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `\bBlowfish\s*\(\s*key\s*:`,
			ObjectType:    "",
			MethodName:    "Blowfish",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "CryptoSwift Blowfish cipher — 64-bit block size is vulnerable to Sweet32 birthday attacks (CVE-2016-2183); use AES-256-GCM instead",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "swift.cryptoswift.rc4",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `\bRC4\s*\(\s*key\s*:`,
			ObjectType:    "",
			MethodName:    "RC4",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "CryptoSwift RC4 stream cipher — banned for TLS use by RFC 7465 (2015) due to multiple plaintext-recovery attacks; use ChaCha20-Poly1305 or AES-GCM instead",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "swift.cryptoswift.rc2",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `\bRC2\s*\(\s*key\s*:`,
			ObjectType:    "",
			MethodName:    "RC2",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "CryptoSwift RC2 cipher — 64-bit block export-grade cipher with practical related-key attacks; use AES-256-GCM instead",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// --- CommonCrypto legacy hashes CC_MD2 / CC_MD4 (CWE-328) ---
		// CommonCrypto still ships CC_MD2 and CC_MD4 entry points despite both
		// algorithms being cryptographically dead (MD2 collision: Muller 2004;
		// MD4 collision: Dobbertin 1996). They are weaker than MD5 and have no
		// legitimate use in new code. Apple deprecated the CC_MD* family in
		// macOS 10.15 in favor of CryptoKit; flag any invocation regardless.
		{
			ID:            "swift.commoncrypto.cc_md2",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `CC_MD2\s*\(`,
			ObjectType:    "",
			MethodName:    "CC_MD2",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "CommonCrypto CC_MD2 — MD2 is cryptographically broken and deprecated in macOS 10.15; use SHA-256 or SHA-3",
			CWEID:         "CWE-328",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "swift.commoncrypto.cc_md4",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `CC_MD4\s*\(`,
			ObjectType:    "",
			MethodName:    "CC_MD4",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "CommonCrypto CC_MD4 — MD4 is cryptographically broken (Dobbertin 1996) and deprecated in macOS 10.15; use SHA-256 or SHA-3",
			CWEID:         "CWE-328",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// --- HTTP Header Injection (CWE-113) ---
		{
			ID:            "swift.httpheader.set",
			Category:      taint.SnkHeader,
			Language:      rules.LangSwift,
			Pattern:       `\.setValue\(\s*.*forHTTPHeaderField:|\.addValue\(\s*.*forHTTPHeaderField:`,
			ObjectType:    "URLRequest",
			MethodName:    "setValue(forHTTPHeaderField:)",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "HTTP header set with potentially tainted value",
			CWEID:         "CWE-113",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.vapor.response.headers",
			Category:      taint.SnkHeader,
			Language:      rules.LangSwift,
			Pattern:       `res\.headers\.add\(|res\.headers\.replaceOrAdd\(`,
			ObjectType:    "Response",
			MethodName:    "res.headers.add",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Vapor response header with potentially tainted value",
			CWEID:         "CWE-113",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.httpfield.init",
			Category:      taint.SnkHeader,
			Language:      rules.LangSwift,
			Pattern:       `HTTPField\(\s*name:`,
			ObjectType:    "HTTPField",
			MethodName:    "HTTPField",
			DangerousArgs: []int{1},
			Severity:      rules.Medium,
			Description:   "swift-http-types HTTPField construction with potentially tainted header value (CVE-2022-3215)",
			CWEID:         "CWE-113",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.nio.httpresponsehead.init",
			Category:      taint.SnkHeader,
			Language:      rules.LangSwift,
			Pattern:       `HTTPResponseHead\(`,
			ObjectType:    "HTTPResponseHead",
			MethodName:    "HTTPResponseHead",
			DangerousArgs: []int{2},
			Severity:      rules.Medium,
			Description:   "SwiftNIO HTTP response head with potentially tainted headers (CVE-2022-3215)",
			CWEID:         "CWE-113",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.hummingbird.response.header",
			Category:      taint.SnkHeader,
			Language:      rules.LangSwift,
			Pattern:       `\.headerFields\.append\s*\(`,
			ObjectType:    "headerFields",
			MethodName:    "headerFields.append",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Hummingbird/swift-http-types header field append with potentially tainted value",
			CWEID:         "CWE-113",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Open Redirect (CWE-601) ---
		{
			ID:            "swift.vapor.redirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangSwift,
			Pattern:       `req\.redirect\(\s*to:|\.redirect\(\s*to:`,
			ObjectType:    "Request",
			MethodName:    "redirect(to:)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Vapor redirect with potentially tainted URL",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Deserialization (CWE-502) ---
		{
			ID:            "swift.nskeyedunarchiver",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangSwift,
			Pattern:       `NSKeyedUnarchiver\.unarchiveObject\(|NSKeyedUnarchiver\.unarchivedObject\(`,
			ObjectType:    "NSKeyedUnarchiver",
			MethodName:    "unarchiveObject",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "NSKeyedUnarchiver deserialization of potentially untrusted data",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- File operations (CWE-22) ---
		{
			ID:            "swift.filemanager.copyitem",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `FileManager\.default\.copyItem\s*\(`,
			ObjectType:    "FileManager",
			MethodName:    "copyItem",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "File copy with potentially tainted paths",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.filemanager.moveitem",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `FileManager\.default\.moveItem\s*\(`,
			ObjectType:    "FileManager",
			MethodName:    "moveItem",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "File move with potentially tainted paths",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.filemanager.createsymboliclink",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `FileManager\.default\.createSymbolicLink\s*\(`,
			ObjectType:    "FileManager",
			MethodName:    "createSymbolicLink",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Symlink creation with potentially tainted paths",
			CWEID:         "CWE-59",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- ReDoS (CWE-1333) ---
		{
			ID:            "swift.nsregularexpression",
			Category:      taint.SnkEval,
			Language:      rules.LangSwift,
			Pattern:       `NSRegularExpression\s*\(|try\s+NSRegularExpression\s*\(`,
			ObjectType:    "NSRegularExpression",
			MethodName:    "NSRegularExpression",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Regex construction with potentially tainted pattern (ReDoS risk)",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},
		// Swift 5.7+ `Regex` runtime initializer (CWE-1333) — the throwing
		// `Regex(_ pattern: String)` compiles a pattern from a *runtime* String,
		// so an attacker-controlled pattern can trigger catastrophic backtracking
		// (ReDoS). This is the dynamic-pattern form only: the `/.../ ` regex
		// literal and the `Regex { … }` RegexBuilder DSL are compile-time
		// checked and are NOT matched (different delimiters / braces). The
		// initializer is `throws`, so the call site is always `try` / `try!` /
		// `try?` — anchoring on `\btry[!?]?\s+Regex\s*\(` both scopes the match
		// to the constructor and avoids substring hits inside identifiers like
		// `MyRegex(` or `NSRegularExpression(`. Categorised under SnkRegexDoS
		// (medium DoS) — not SnkEval — to match the threat, and neutralized by
		// the existing `NSRegularExpression.escapedPattern(for:)` sanitizer.
		{
			ID:            "swift.regex.init.runtime",
			Category:      taint.SnkRegexDoS,
			Language:      rules.LangSwift,
			Pattern:       `\btry[!?]?\s+Regex\s*\(`,
			ObjectType:    "Regex",
			MethodName:    "Regex",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Swift Regex(_ pattern: String) runtime initializer compiled from a potentially tainted pattern string — catastrophic backtracking on an attacker-controlled pattern is ReDoS (CWE-1333). The `/.../ ` regex literal and `Regex { … }` builder DSL are compile-time checked and safe; escape user input with NSRegularExpression.escapedPattern(for:) or validate it before compiling a dynamic pattern.",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- iOS deep link redirect ---
		{
			ID:            "swift.uiapplication.open",
			Category:      taint.SnkRedirect,
			Language:      rules.LangSwift,
			Pattern:       `UIApplication\.shared\.open\s*\(`,
			ObjectType:    "UIApplication",
			MethodName:    "open",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "iOS URL open with potentially tainted URL (deep link redirect)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Core Data NSPredicate injection (CWE-943) ---
		{
			ID:            "swift.nspredicate.format",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `NSPredicate\(\s*format:\s*"[^"]*\\[^"]*"`,
			ObjectType:    "NSPredicate",
			MethodName:    "NSPredicate(format:)",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "NSPredicate with string interpolation enables predicate injection",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.nspredicate.format.concat",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `NSPredicate\(\s*format:\s*[^)]*\+\s*\w`,
			ObjectType:    "NSPredicate",
			MethodName:    "NSPredicate(format: ... + var)",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "NSPredicate with string concatenation enables predicate injection",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.nsexpression",
			Category:      taint.SnkEval,
			Language:      rules.LangSwift,
			Pattern:       `NSExpression\(\s*format:`,
			ObjectType:    "NSExpression",
			MethodName:    "NSExpression(format:)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "NSExpression with tainted format string allows code execution",
			CWEID:         "CWE-95",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Fluent / SQLKit raw SQL (CWE-89) ---
		//
		// Vapor's ORM (Fluent) and its SQL layer (SQLKit) expose `.raw(_:)` as
		// the raw-SQL escape hatch — the canonical server-side SQL-injection
		// vector in Swift web code:
		//     try await req.db.raw("SELECT * FROM users WHERE id = \(userId)")
		//     try await db.raw(SQLQueryString("SELECT … '\(name)'")).all()
		// tsflow keys on the bare called method name, so MethodName MUST be the
		// bare `raw` (a dotted/parenthetical name like `db.raw()` or
		// `raw(SQLQueryString)` is mangled by extractMethodNames into an
		// unreachable key — the sink was previously dead). ObjectType is ""
		// (wildcard) to match any receiver (`req.db`, `database`, `conn`, a
		// `SQLDatabase`) — the receiver type is not in the call-node text; the
		// call-anchored Pattern is re-validated by weakSinkPatternOK, and
		// DangerousArgs:[0] requires arg 0 to be tainted, so a parameterized
		// `.raw("… \(bind: userId)")` (the bind: interpolation flows untainted)
		// or a constant `.raw("SELECT 1")` never fires.
		{
			ID:            "swift.fluent.raw",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `\.raw\(\s*"`,
			ObjectType:    "",
			MethodName:    "raw",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Fluent/SQLKit raw SQL query with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.fluent.raw.execute",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `\.raw\(\s*SQLQueryString\(`,
			ObjectType:    "",
			MethodName:    "raw",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Fluent/SQLKit raw SQL with SQLQueryString interpolation",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- MySQLNIO SQL injection (CWE-89) ---
		{
			ID:            "swift.mysqlnio.simplequery",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `\.simpleQuery\s*\(`,
			ObjectType:    "MySQLConnection",
			MethodName:    "simpleQuery",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MySQLNIO simpleQuery executes raw SQL without parameter bindings — SQL injection risk",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Vapor FileIO path traversal (CWE-22) ---
		{
			ID:            "swift.vapor.fileio.streamfile",
			Category:      taint.SnkFileRead,
			Language:      rules.LangSwift,
			Pattern:       `\.fileio\.streamFile\s*\(\s*at:`,
			ObjectType:    "FileIO",
			MethodName:    "streamFile",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Vapor file streaming with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.vapor.fileio.collectfile",
			Category:      taint.SnkFileRead,
			Language:      rules.LangSwift,
			Pattern:       `\.fileio\.collectFile\s*\(\s*at:`,
			ObjectType:    "FileIO",
			MethodName:    "collectFile",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Vapor file collection with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.vapor.fileio.readfile",
			Category:      taint.SnkFileRead,
			Language:      rules.LangSwift,
			Pattern:       `\.fileio\.readFile\s*\(\s*at:`,
			ObjectType:    "FileIO",
			MethodName:    "readFile",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Vapor file read with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.vapor.fileio.writefile",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `\.fileio\.writeFile\s*\(`,
			ObjectType:    "FileIO",
			MethodName:    "writeFile",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "Vapor file write with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Async URLSession SSRF (CWE-918) ---
		{
			ID:            "swift.urlsession.async.ssrf",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `URLSession\.shared\.data\(\s*from:|URLSession\.shared\.data\(\s*for:`,
			ObjectType:    "URLSession",
			MethodName:    "data(from:)/data(for:)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Async URLSession request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "swift.urlsession.async.download.ssrf",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `URLSession\.shared\.download\(\s*from:|URLSession\.shared\.download\(\s*for:`,
			ObjectType:    "URLSession",
			MethodName:    "download(from:)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Async URLSession download with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- WKWebView URL loading (CWE-79/CWE-601) ---
		{
			ID:            "swift.wkwebview.load",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangSwift,
			Pattern:       `\.load\(\s*URLRequest\(|webView\.load\(`,
			ObjectType:    "WKWebView",
			MethodName:    "load(URLRequest)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "WKWebView loading tainted URL (potential phishing/XSS)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Process.run() modern API (CWE-78) ---
		{
			ID:            "swift.process.run",
			Category:      taint.SnkCommand,
			Language:      rules.LangSwift,
			Pattern:       `process\.run\(\)|task\.run\(\)|proc\.run\(\)`,
			ObjectType:    "Process",
			MethodName:    "run()",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Process.run() executes OS command (modern API)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Realm raw query (CWE-89) ---
		{
			ID:            "swift.realm.filter.string",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `\.filter\(\s*"[^"]*\\|\.filter\(\s*NSPredicate\(`,
			ObjectType:    "Realm",
			MethodName:    "filter(NSPredicate)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Realm query with tainted filter predicate",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- SFSafariViewController (CWE-601) ---
		{
			ID:            "swift.sfsafariviewcontroller",
			Category:      taint.SnkRedirect,
			Language:      rules.LangSwift,
			Pattern:       `SFSafariViewController\(\s*url:`,
			ObjectType:    "SFSafariViewController",
			MethodName:    "SFSafariViewController(url:)",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Safari view controller opened with potentially tainted URL",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Vapor WebSocket (CWE-79) ---
		{
			ID:            "swift.vapor.websocket.send",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangSwift,
			Pattern:       `ws\.send\(|websocket\.send\(`,
			ObjectType:    "WebSocket",
			MethodName:    "ws.send()",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Vapor WebSocket send with potentially tainted data",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Alamofire SSRF (CWE-918) ---
		{
			ID:            "swift.alamofire.af.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `AF\.request\s*\(`,
			ObjectType:    "Alamofire",
			MethodName:    "AF.request",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Alamofire HTTP request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "swift.alamofire.af.download",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `AF\.download\s*\(`,
			ObjectType:    "Alamofire",
			MethodName:    "AF.download",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Alamofire file download with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:         "swift.alamofire.af.upload",
			Category:   taint.SnkURLFetch,
			Language:   rules.LangSwift,
			Pattern:    `AF\.upload\s*\(`,
			ObjectType: "Alamofire",
			MethodName: "AF.upload",
			// The SSRF-relevant argument is the destination URL, which is always
			// passed via the `to:` label — positionally index 1 in every overload
			// (`AF.upload(_ data:, to:)` and `AF.upload(multipartFormData:, to:)`).
			// Index 0 is the payload (Data / file URL / multipart closure) and is
			// NOT the request target, so tainting it produced both false positives
			// (tainted form fields + hardcoded URL) and false negatives (hardcoded
			// payload + tainted `to:` URL — the real SSRF). Track index 1.
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "Alamofire file upload to potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "swift.alamofire.session.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `session\.request\s*\(`,
			ObjectType:    "Session",
			MethodName:    "session.request",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Alamofire Session request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "swift.alamofire.session.download",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `session\.download\s*\(`,
			ObjectType:    "Session",
			MethodName:    "session.download",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Alamofire Session download with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- Moya SSRF (CWE-918) ---
		{
			ID:            "swift.moya.provider.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `provider\.request\s*\(`,
			ObjectType:    "MoyaProvider",
			MethodName:    "provider.request",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Moya network request with potentially tainted target (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- AsyncHTTPClient / SwiftNIO SSRF (CWE-918) ---
		{
			ID:            "swift.asynchttp.execute",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `httpClient\.execute\s*\(`,
			ObjectType:    "HTTPClient",
			MethodName:    "httpClient.execute",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "AsyncHTTPClient request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "swift.asynchttp.request.url",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `HTTPClientRequest\s*\(\s*url:`,
			ObjectType:    "HTTPClientRequest",
			MethodName:    "HTTPClientRequest",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "AsyncHTTPClient modern async request constructed with potentially tainted URL string (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "swift.asynchttp.legacyrequest.url",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `HTTPClient\.Request\s*\(\s*url:`,
			ObjectType:    "HTTPClient",
			MethodName:    "Request",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "AsyncHTTPClient legacy request constructor (HTTPClient.Request) with potentially tainted URL string (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "swift.asynchttp.shared.execute",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `HTTPClient\.shared\.execute\s*\(`,
			ObjectType:    "HTTPClient.shared",
			MethodName:    "execute",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "AsyncHTTPClient shared singleton execute() with potentially tainted URL request (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "swift.asynchttp.shared.get",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `HTTPClient\.shared\.(?:get|post|put|delete|patch)\s*\(\s*url:`,
			ObjectType:    "HTTPClient.shared",
			MethodName:    "get/post/put/delete/patch",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "AsyncHTTPClient shared singleton HTTP convenience method with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- SwiftNIO NonBlockingFileIO / NIOFileHandle path traversal (CWE-22) ---
		{
			ID:            "swift.nio.fileio.openfile",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `\.(?:fileIO|fileio)\.openFile\s*\(\s*path:`,
			ObjectType:    "",
			MethodName:    "openFile",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SwiftNIO NonBlockingFileIO.openFile(path:) opens a file with potentially tainted path (path traversal / arbitrary file write)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.nio.fileio.readfile",
			Category:      taint.SnkFileRead,
			Language:      rules.LangSwift,
			Pattern:       `\.(?:fileIO|fileio)\.read(?:File|EntireFile)\s*\(\s*path:`,
			ObjectType:    "",
			MethodName:    "readFile/readEntireFile",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SwiftNIO NonBlockingFileIO reads a file with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.nio.filehandle.init",
			Category:      taint.SnkFileRead,
			Language:      rules.LangSwift,
			Pattern:       `NIOFileHandle\s*\(\s*_?path:`,
			ObjectType:    "NIOFileHandle",
			MethodName:    "NIOFileHandle",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SwiftNIO NIOFileHandle constructed with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Kingfisher image loading SSRF (CWE-918) ---
		{
			ID:            "swift.kingfisher.setimage",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `\.kf\.setImage\s*\(\s*with:`,
			ObjectType:    "Kingfisher",
			MethodName:    "kf.setImage(with:)",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Kingfisher image loading with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- Weak PRNG (CWE-330) ---
		{
			ID:            "swift.prng.drand48",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `drand48\s*\(`,
			ObjectType:    "",
			MethodName:    "drand48()",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Weak PRNG drand48() — linear congruential, predictable for tokens/keys",
			CWEID:         "CWE-330",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "swift.prng.rand",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `\brand\s*\(\s*\)`,
			ObjectType:    "",
			MethodName:    "rand()",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Weak PRNG rand() — cyclic low bits, modulo bias, not cryptographically secure",
			CWEID:         "CWE-330",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "swift.prng.random",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `\brandom\s*\(\s*\)`,
			ObjectType:    "",
			MethodName:    "random()",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Weak PRNG random() — not cryptographically secure, predictable seed",
			CWEID:         "CWE-330",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// --- Insecure TLS / Certificate Bypass (CWE-295) ---
		{
			ID:         "swift.tls.urlcredential.trust",
			Category:   taint.SnkCrypto,
			Language:   rules.LangSwift,
			Pattern:    `URLCredential\(\s*trust:`,
			ObjectType: "URLCredential",
			// MethodName carries the arg-label form so the swiftArgLabels gate
			// REQUIRES the `trust:` label: this sink is ONLY the cert-bypass init
			// URLCredential(trust:). A bare "URLCredential" MethodName matched
			// every URLCredential(...) call — including the benign HTTP-Basic
			// URLCredential(user:password:) init — producing crypto FPs on any
			// credential-passing code (e.g. Alamofire's authenticate()).
			MethodName:    "URLCredential(trust:)",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "URLCredential(trust:) can bypass TLS certificate validation (MITM risk)",
			CWEID:         "CWE-295",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "swift.tls.allowsinvalidcerts",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `allowsExpiredCertificates\s*=\s*true|allowsExpiredRoots\s*=\s*true|validatesDomainName\s*=\s*false`,
			ObjectType:    "ServerTrustPolicy",
			MethodName:    "TLS policy override",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "TLS validation disabled — allows expired certs or skips domain validation",
			CWEID:         "CWE-295",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// --- XXE: XML External Entity Injection (CWE-611) ---
		{
			ID:            "swift.xmlparser.xxe",
			Category:      taint.SnkEval,
			Language:      rules.LangSwift,
			Pattern:       `shouldResolveExternalEntities\s*=\s*true`,
			ObjectType:    "XMLParser",
			MethodName:    "shouldResolveExternalEntities = true",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "XMLParser XXE enabled — allows file read, SSRF, DoS via external entities",
			CWEID:         "CWE-611",
			OWASPCategory: "A05:2021-Security Misconfiguration",
		},

		// --- Unsafe Memory Operations (CWE-119) ---
		{
			ID:            "swift.unsafe.mutablepointer.allocate",
			Category:      taint.SnkEval,
			Language:      rules.LangSwift,
			Pattern:       `UnsafeMutablePointer<[^>]+>\.allocate\s*\(`,
			ObjectType:    "UnsafeMutablePointer",
			MethodName:    "allocate",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Manual pointer allocation — no bounds checking, potential buffer overflow",
			CWEID:         "CWE-119",
			OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
		},
		{
			ID:            "swift.unsafe.rawpointer.allocate",
			Category:      taint.SnkEval,
			Language:      rules.LangSwift,
			Pattern:       `UnsafeMutableRawPointer\.allocate\s*\(`,
			ObjectType:    "UnsafeMutableRawPointer",
			MethodName:    "allocate",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Raw pointer allocation — type-unaware memory, potential corruption",
			CWEID:         "CWE-119",
			OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
		},
		{
			ID:            "swift.unsafe.bindmemory",
			Category:      taint.SnkEval,
			Language:      rules.LangSwift,
			Pattern:       `\.bindMemory\(\s*to:`,
			ObjectType:    "",
			MethodName:    "bindMemory",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Memory type rebinding — UB if memory is already bound to a different type",
			CWEID:         "CWE-843",
			OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
		},
		{
			ID:            "swift.unsafe.assumingmemorybound",
			Category:      taint.SnkEval,
			Language:      rules.LangSwift,
			Pattern:       `\.assumingMemoryBound\(\s*to:`,
			ObjectType:    "",
			MethodName:    "assumingMemoryBound",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Unsafe memory type assumption — undefined behavior if assumption is wrong",
			CWEID:         "CWE-843",
			OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
		},

		// --- Trust Boundary Violations (CWE-501) ---
		{
			ID:            "swift.trust.nsuseractivity",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangSwift,
			Pattern:       `NSUserActivity\(\s*activityType:`,
			ObjectType:    "NSUserActivity",
			MethodName:    "NSUserActivity",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "NSUserActivity Handoff sends data to other devices — trust boundary crossing",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "swift.trust.keychain.accessgroup",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangSwift,
			Pattern:       `kSecAttrAccessGroup\s*:`,
			ObjectType:    "Security",
			MethodName:    "kSecAttrAccessGroup",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Keychain access group shares data between apps — trust boundary crossing",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "swift.trust.userdefaults.suitename",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangSwift,
			Pattern:       `UserDefaults\(\s*suiteName:`,
			ObjectType:    "UserDefaults",
			MethodName:    "UserDefaults",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "App Group UserDefaults shares data with extensions — trust boundary crossing",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "swift.trust.uiactivity",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangSwift,
			Pattern:       `UIActivityViewController\(\s*activityItems:`,
			ObjectType:    "UIActivityViewController",
			MethodName:    "UIActivityViewController",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Share sheet exposes data to third-party extensions — trust boundary crossing",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},

		// --- Additional Trust Boundary (CWE-501) ---
		{
			ID:            "swift.trust.userdefaults.set",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangSwift,
			Pattern:       `UserDefaults\.standard\.set\s*\(`,
			ObjectType:    "UserDefaults",
			MethodName:    "set",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Tainted data stored in UserDefaults — accessible via backup extraction and app group sharing",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "swift.trust.pasteboard.setvalue",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangSwift,
			Pattern:       `UIPasteboard\.general\.setValue\s*\(`,
			ObjectType:    "UIPasteboard",
			MethodName:    "setValue",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Tainted data written to system pasteboard via setValue — accessible by all apps on device",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "swift.trust.pasteboard.setobjects",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangSwift,
			Pattern:       `UIPasteboard\.general\.setObjects\s*\(`,
			ObjectType:    "UIPasteboard",
			MethodName:    "setObjects",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Tainted data written to system pasteboard via setObjects — accessible by all apps on device",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "swift.trust.vapor.session",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangSwift,
			Pattern:       `req\.session\.data\[`,
			ObjectType:    "Session",
			MethodName:    "session.data",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Unsanitized tainted data stored in Vapor session — trust boundary between request and session state",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},

		// --- File Read / Path Traversal (CWE-22) ---
		{
			ID:            "swift.string.contentsoffile.read",
			Category:      taint.SnkFileRead,
			Language:      rules.LangSwift,
			Pattern:       `String\(\s*contentsOfFile:|String\(\s*contentsOf:\s*URL\(\s*fileURLWithPath:`,
			ObjectType:    "String",
			MethodName:    "String(contentsOfFile:)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File read with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.data.contentsof.read",
			Category:      taint.SnkFileRead,
			Language:      rules.LangSwift,
			Pattern:       `Data\(\s*contentsOf:\s*URL\(\s*fileURLWithPath:`,
			ObjectType:    "Data",
			MethodName:    "Data(contentsOf:)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Binary file read with potentially tainted path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.filehandle.read",
			Category:      taint.SnkFileRead,
			Language:      rules.LangSwift,
			Pattern:       `FileHandle\(\s*forReadingAtPath:|FileHandle\(\s*forReadingFrom:`,
			ObjectType:    "FileHandle",
			MethodName:    "FileHandle(forReadingAtPath:)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File handle opened for reading with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.filemanager.fileexists",
			Category:      taint.SnkFileRead,
			Language:      rules.LangSwift,
			Pattern:       `FileManager\.default\.fileExists\(\s*atPath:`,
			ObjectType:    "FileManager",
			MethodName:    "fileExists(atPath:)",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "File existence check with tainted path (information disclosure)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Hummingbird framework response sinks ---
		{
			ID:            "swift.hummingbird.response.body",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangSwift,
			Pattern:       `HBResponse\(\s*status:.*body:|\.body\s*=\s*HBResponseBody\(`,
			ObjectType:    "HBResponse",
			MethodName:    "HBResponse(body:)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Hummingbird HTTP response with potentially tainted body (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.hummingbird.response.redirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangSwift,
			Pattern:       `HBResponse\(\s*status:\s*\.(?:movedPermanently|temporaryRedirect|seeOther).*headers:`,
			ObjectType:    "HBResponse",
			MethodName:    "HBResponse(redirect)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Hummingbird redirect response with potentially tainted URL",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.nsworkspace.open",
			Category:      taint.SnkRedirect,
			Language:      rules.LangSwift,
			Pattern:       `NSWorkspace\.shared\.open\s*\(`,
			ObjectType:    "NSWorkspace",
			MethodName:    "NSWorkspace.shared.open",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "macOS NSWorkspace opens URL in default handler with potentially tainted URL (phishing/file-scheme abuse)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.uiwebview.loadrequest",
			Category:      taint.SnkRedirect,
			Language:      rules.LangSwift,
			Pattern:       `\.loadRequest\s*\(\s*URLRequest\(|webView\.loadRequest\s*\(`,
			ObjectType:    "",
			MethodName:    "loadRequest",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Legacy UIWebView loading potentially tainted URL via loadRequest(URLRequest) (open redirect/phishing)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.aswebauthsession.init",
			Category:      taint.SnkRedirect,
			Language:      rules.LangSwift,
			Pattern:       `ASWebAuthenticationSession\s*\(\s*url:`,
			ObjectType:    "ASWebAuthenticationSession",
			MethodName:    "ASWebAuthenticationSession",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ASWebAuthenticationSession with potentially tainted URL (OAuth phishing / credential exfiltration)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.lsopencfurlref",
			Category:      taint.SnkRedirect,
			Language:      rules.LangSwift,
			Pattern:       `LSOpenCFURLRef\s*\(`,
			ObjectType:    "",
			MethodName:    "LSOpenCFURLRef",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "macOS Launch Services opens URL with potentially tainted CFURL (redirect/file-scheme abuse)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- URLSession upload (data exfiltration) ---
		{
			ID:            "swift.urlsession.upload",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `URLSession\.shared\.upload\(\s*for:|\.uploadTask\(\s*with:`,
			ObjectType:    "URLSession",
			MethodName:    "upload(for:)/uploadTask(with:)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "URLSession upload with potentially tainted destination (SSRF/exfil)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- SDWebImage SSRF (CWE-918) ---
		{
			ID:            "swift.sdwebimage.setimage",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `\.sd_setImage\s*\(\s*with:`,
			ObjectType:    "SDWebImage",
			MethodName:    "sd_setImage(with:)",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "SDWebImage image loading with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		// SwiftUI's built-in AsyncImage (iOS 15+/macOS 12+) fetches the URL it
		// is initialized with. A user-controlled URL reaching AsyncImage(url:)
		// causes the app to issue an arbitrary outbound request (image SSRF),
		// the same class of issue already modeled for Kingfisher/SDWebImage.
		// Constructor match: receiver is empty, callMethod == ObjectType.
		{
			ID:            "swift.swiftui.asyncimage",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `\bAsyncImage\s*\(\s*url:`,
			ObjectType:    "AsyncImage",
			MethodName:    "AsyncImage",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "SwiftUI AsyncImage loading with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		// Nuke (one of the most widely used Swift image libraries) — the classic
		// UIKit/AppKit helper Nuke.loadImage(with:into:) fetches the supplied
		// URL/ImageRequest. Receiver is literally `Nuke`, so ObjectType "Nuke"
		// matches without firing on unrelated loadImage methods.
		{
			ID:            "swift.nuke.loadimage",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `\bNuke\.loadImage\s*\(`,
			ObjectType:    "Nuke",
			MethodName:    "loadImage",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Nuke.loadImage with potentially tainted URL/ImageRequest (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		// NukeUI's SwiftUI LazyImage(url:) — modern Nuke entry point — fetches
		// the URL it is constructed with. Constructor match on the LazyImage type.
		{
			ID:            "swift.nukeui.lazyimage",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `\bLazyImage\s*\(\s*url:`,
			ObjectType:    "LazyImage",
			MethodName:    "LazyImage",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "NukeUI LazyImage loading with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- XPath/XQuery injection (CWE-643) ---
		{
			ID:            "swift.xmldocument.xpath",
			Category:      taint.SnkXPath,
			Language:      rules.LangSwift,
			Pattern:       `\.nodes\(\s*forXPath:|\.objectsForXQuery\s*\(|XMLNode\.nodes\(\s*forXPath:`,
			ObjectType:    "XMLDocument",
			MethodName:    "nodes(forXPath:)/objectsForXQuery()",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XPath/XQuery evaluation with potentially tainted expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- libxml2 C interop XPath (CWE-643) ---
		{
			ID:            "swift.libxml2.xpathevalexpression",
			Category:      taint.SnkXPath,
			Language:      rules.LangSwift,
			Pattern:       `xmlXPathEvalExpression\s*\(`,
			ObjectType:    "",
			MethodName:    "xmlXPathEvalExpression",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "libxml2 XPath expression evaluation via C interop with potentially tainted expression string",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.libxml2.xpatheval",
			Category:      taint.SnkXPath,
			Language:      rules.LangSwift,
			Pattern:       `xmlXPathEval\s*\(`,
			ObjectType:    "",
			MethodName:    "xmlXPathEval",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "libxml2 legacy XPath evaluation via C interop with potentially tainted expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.libxml2.xpathnodeeval",
			Category:      taint.SnkXPath,
			Language:      rules.LangSwift,
			Pattern:       `xmlXPathNodeEval\s*\(`,
			ObjectType:    "",
			MethodName:    "xmlXPathNodeEval",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "libxml2 per-node XPath evaluation via C interop with potentially tainted expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- MongoSwift / MongoKitten NoSQL injection (CWE-943) ---
		{
			ID:            "swift.mongoswift.collection.find",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `MongoCollection.*\.find\s*\(`,
			ObjectType:    "Collection",
			MethodName:    "find",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoSwift collection find with potentially tainted filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.mongokitten.collection.find",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `\.find\s*\(\s*where:`,
			ObjectType:    "Collection",
			MethodName:    "find",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoKitten collection find with potentially tainted query (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.mongoswift.collection.findone",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `\.findOne\s*\(`,
			ObjectType:    "",
			MethodName:    "findOne",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoSwift findOne with potentially tainted filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.mongoswift.collection.aggregate",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `MongoCollection.*\.aggregate\s*\(|\.buildAggregate\s*\(`,
			ObjectType:    "Collection",
			MethodName:    "aggregate/buildAggregate",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoDB aggregation pipeline with potentially tainted stages (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.mongoswift.collection.updateone",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `MongoCollection.*\.updateOne\s*\(`,
			ObjectType:    "Collection",
			MethodName:    "updateOne",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoSwift updateOne with potentially tainted filter/update (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.mongoswift.collection.updatemany",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `MongoCollection.*\.updateMany\s*\(`,
			ObjectType:    "Collection",
			MethodName:    "updateMany",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoSwift updateMany with potentially tainted filter/update (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.mongoswift.collection.deleteone",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `MongoCollection.*\.deleteOne\s*\(`,
			ObjectType:    "Collection",
			MethodName:    "deleteOne",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoSwift deleteOne with potentially tainted filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.mongoswift.collection.deletemany",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `MongoCollection.*\.deleteMany\s*\(`,
			ObjectType:    "Collection",
			MethodName:    "deleteMany",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoSwift deleteMany with potentially tainted filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.mongoswift.collection.findoneandupdate",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `\.findOneAndUpdate\s*\(`,
			ObjectType:    "",
			MethodName:    "findOneAndUpdate",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoSwift findOneAndUpdate with potentially tainted filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.mongoswift.collection.findoneanddelete",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `\.findOneAndDelete\s*\(`,
			ObjectType:    "",
			MethodName:    "findOneAndDelete",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoSwift findOneAndDelete with potentially tainted filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.mongoswift.collection.findoneandreplace",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `\.findOneAndReplace\s*\(`,
			ObjectType:    "",
			MethodName:    "findOneAndReplace",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoSwift findOneAndReplace with potentially tainted filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.mongoswift.collection.replaceone",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `MongoCollection.*\.replaceOne\s*\(`,
			ObjectType:    "Collection",
			MethodName:    "replaceOne",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoSwift replaceOne with potentially tainted filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.mongokitten.collection.deleteone",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `\.deleteOne\s*\(\s*where:`,
			ObjectType:    "Collection",
			MethodName:    "deleteOne",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoKitten deleteOne with potentially tainted query (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.mongokitten.collection.upsert",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `\.upsert\s*\([^)]*where:`,
			ObjectType:    "",
			MethodName:    "upsert",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoKitten upsert with potentially tainted query (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.mongokitten.collection.count",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `\.count\s*\(\s*where:`,
			ObjectType:    "Collection",
			MethodName:    "count",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "MongoKitten count with potentially tainted query (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Additional deserialization sinks (CWE-502) ---
		{
			ID:            "swift.nsunarchiver.unarchiveobject",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangSwift,
			Pattern:       `NSUnarchiver\.unarchiveObject\s*\(`,
			ObjectType:    "NSUnarchiver",
			MethodName:    "unarchiveObject",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Deprecated NSUnarchiver deserialization of untrusted data (no class validation)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "swift.propertylistserialization.propertylist",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangSwift,
			Pattern:       `PropertyListSerialization\.propertyList\(\s*from:`,
			ObjectType:    "PropertyListSerialization",
			MethodName:    "propertyList",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Property list deserialization of potentially untrusted data",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "swift.jsonserialization.jsonobject",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangSwift,
			Pattern:       `JSONSerialization\.jsonObject\(\s*with:`,
			ObjectType:    "JSONSerialization",
			MethodName:    "jsonObject",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "JSON deserialization of potentially untrusted data into untyped Any",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "swift.nskeyedunarchiver.toplevelobject",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangSwift,
			Pattern:       `NSKeyedUnarchiver\.unarchiveTopLevelObjectWithData\s*\(`,
			ObjectType:    "NSKeyedUnarchiver",
			MethodName:    "unarchiveTopLevelObjectWithData",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Deprecated NSKeyedUnarchiver top-level object deserialization without class validation",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "swift.nscoder.decodeobject",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangSwift,
			Pattern:       `\.decodeObject\(\s*forKey:`,
			ObjectType:    "",
			MethodName:    "decodeObject",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "NSCoder.decodeObject without type constraint — allows arbitrary class instantiation from untrusted archive",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- Process/NSAppleScript command execution (CWE-78) ---
		{
			ID:            "swift.process.executableurl",
			Category:      taint.SnkCommand,
			Language:      rules.LangSwift,
			Pattern:       `\.executableURL\s*=\s*URL\(`,
			ObjectType:    "Process",
			MethodName:    "executableURL",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Process.executableURL set with potentially tainted URL (modern API replacing launchPath)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.nsapplescript.init",
			Category:      taint.SnkCommand,
			Language:      rules.LangSwift,
			Pattern:       `NSAppleScript\(\s*source:`,
			ObjectType:    "",
			MethodName:    "NSAppleScript",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "NSAppleScript initialized with potentially tainted script source (macOS code injection)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Redis Command Injection (CWE-77) ---
		{
			ID:            "swift.redistack.send.command",
			Category:      taint.SnkCommand,
			Language:      rules.LangSwift,
			Pattern:       `(?:redis|redisConn|redisClient)\.send\(\s*command:`,
			ObjectType:    "RedisClient",
			MethodName:    "send",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "RediStack raw Redis command execution with potentially tainted arguments",
			CWEID:         "CWE-77",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.redistack.eval",
			Category:      taint.SnkEval,
			Language:      rules.LangSwift,
			Pattern:       `(?:redis|redisConn|redisClient)\.eval\s*\(`,
			ObjectType:    "RedisClient",
			MethodName:    "eval",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "RediStack Redis Lua script evaluation with potentially tainted script",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- LDAP Injection (CWE-90) ---

		// PerfectLDAP search with filter parameter
		{
			ID:            "swift.ldap.search",
			Category:      taint.SnkLDAP,
			Language:      rules.LangSwift,
			Pattern:       `\.search\s*\(\s*base:`,
			ObjectType:    "LDAP",
			MethodName:    "search",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "PerfectLDAP search with potentially tainted filter (LDAP injection)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		// PerfectLDAP login/bind
		{
			ID:            "swift.ldap.login",
			Category:      taint.SnkLDAP,
			Language:      rules.LangSwift,
			Pattern:       `LDAP\s*\(.*\)\.login\s*\(|ldap\.login\s*\(`,
			ObjectType:    "LDAP",
			MethodName:    "login",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "PerfectLDAP bind with potentially tainted DN (DN injection)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		// PerfectLDAP modify
		{
			ID:            "swift.ldap.modify",
			Category:      taint.SnkLDAP,
			Language:      rules.LangSwift,
			Pattern:       `\.modify\s*\(\s*distinguishedName:`,
			ObjectType:    "LDAP",
			MethodName:    "modify",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "PerfectLDAP modify with potentially tainted DN",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		// PerfectLDAP add
		{
			ID:            "swift.ldap.add",
			Category:      taint.SnkLDAP,
			Language:      rules.LangSwift,
			Pattern:       `\.add\s*\(\s*distinguishedName:`,
			ObjectType:    "LDAP",
			MethodName:    "add",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "PerfectLDAP add with potentially tainted DN",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		// macOS OpenDirectory ODQuery
		{
			ID:            "swift.opendirectory.odquery",
			Category:      taint.SnkLDAP,
			Language:      rules.LangSwift,
			Pattern:       `ODQuery\s*\(\s*node:`,
			ObjectType:    "",
			MethodName:    "ODQuery",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "macOS OpenDirectory query with potentially tainted search values",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		// C libldap search (bridged to Swift)
		{
			ID:            "swift.libldap.search",
			Category:      taint.SnkLDAP,
			Language:      rules.LangSwift,
			Pattern:       `ldap_search_ext(?:_s)?\s*\(`,
			ObjectType:    "",
			MethodName:    "ldap_search_ext_s/ldap_search_ext",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "C libldap search with potentially tainted filter (bridged to Swift)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		// C libldap bind (bridged to Swift)
		{
			ID:            "swift.libldap.bind",
			Category:      taint.SnkLDAP,
			Language:      rules.LangSwift,
			Pattern:       `ldap_(?:simple_)?bind_s\s*\(`,
			ObjectType:    "",
			MethodName:    "ldap_bind_s/ldap_simple_bind_s",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "C libldap bind with potentially tainted DN (bridged to Swift)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		// =====================================================================
		// JWT signature verification bypass (CWE-347)
		// =====================================================================

		// --- SwiftJWT (Kitura) static JWT.decode ---
		// `JWT<T>.decode(token)` parses a JWT string and returns the claims
		// without performing any signature verification. `JWT<T>.verify(token,
		// using: verifier)` is the safe counterpart.
		{
			ID:            "swift.jwt.kitura.decode",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `JWT(?:<[^>]+>)?\.decode\s*\(`,
			ObjectType:    "JWT",
			MethodName:    "decode",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SwiftJWT (Kitura) JWT.decode parses a JWT without verifying its signature; use JWT<T>.verify(token, using: verifier) or pass a non-.none JWTVerifier to JWT(jwtString:verifier:) instead",
			CWEID:         "CWE-347",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// --- Auth0 JWTDecode.swift qualified decode ---
		// The `decode(jwt:)` free function from auth0/JWTDecode.swift is
		// documented as a client-side-only helper that never performs any
		// cryptographic verification. This entry catches the module-qualified
		// form `JWTDecode.decode(jwt: token)`; trusting the return value on a
		// server (or before authz decisions) is CWE-347.
		{
			ID:            "swift.jwt.auth0.decode",
			Category:      taint.SnkCrypto,
			Language:      rules.LangSwift,
			Pattern:       `JWTDecode\.decode\s*\(\s*jwt\s*:`,
			ObjectType:    "JWTDecode",
			MethodName:    "decode",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Auth0 JWTDecode.swift decode(jwt:) extracts JWT claims without any signature verification; library docs state it is for client-side inspection only and must not be used for authentication",
			CWEID:         "CWE-347",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// =====================================================================
		// PostgresNIO raw-SQL injection (CWE-89)
		// =====================================================================
		//
		// PostgresNIO is Vapor's official Postgres driver (vapor/postgres-nio).
		// Modern usage is `conn.query(PostgresQuery)` where PostgresQuery is
		// built via ExpressibleByStringInterpolation — interpolated values
		// become bound parameters, so `"SELECT … WHERE id = \(id)"` is safe.
		//
		// Two escape hatches bypass that safety and introduce SQL injection:
		//   1. `PostgresQuery(unsafeSQL: rawString, binds: …)` — the
		//      constructor is explicitly named `unsafeSQL` to signal that the
		//      caller is assembling the SQL string themselves. Any
		//      user-controlled concatenation/interpolation into `rawString`
		//      is SQL injection.
		//   2. Legacy `conn.query(_ string: String, _ binds: [PostgresData])`
		//      and `conn.simpleQuery(_ string: String)` take a raw SQL
		//      string as arg 0 — the simpleQuery form is already caught by
		//      swift.mysqlnio.simplequery (same `.simpleQuery(` shape).
		//
		// Common receivers: `conn`, `connection`, `db`, `postgres` — all
		// covered by the "Connection" receiver heuristic in
		// tsflow/matcher.go (`catLower` contains "connection").

		{
			ID:            "swift.postgresnio.unsafesql",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `PostgresQuery\s*\(\s*unsafeSQL\s*:`,
			ObjectType:    "PostgresQuery",
			MethodName:    "PostgresQuery",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PostgresNIO PostgresQuery(unsafeSQL:) constructs a raw SQL query without parameter binding — the `unsafeSQL:` label is the library's explicit opt-out of safe string interpolation. Any tainted data in the SQL string is SQL injection (CWE-89). Use `PostgresQuery` via ExpressibleByStringInterpolation (e.g. `\"SELECT … WHERE id = \\(id)\"`) so interpolated values are bound as parameters.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.postgresnio.query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `(?:conn|connection|db|postgres)\.query\s*\(\s*"`,
			ObjectType:    "PostgresConnection",
			MethodName:    "query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PostgresNIO PostgresConnection.query(_:, _:) accepts a raw SQL string as arg 0 plus optional `[PostgresData]` bindings. String concatenation/interpolation into arg 0 is SQL injection (CWE-89). Use `PostgresQuery` string interpolation — `conn.query(\"SELECT … WHERE id = \\(id)\")` — so interpolated values are sent as bound parameters instead.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.postgresnio.simplequery.conn",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `(?:conn|connection|db|postgres)\.simpleQuery\s*\(`,
			ObjectType:    "PostgresConnection",
			MethodName:    "simpleQuery",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PostgresNIO PostgresConnection.simpleQuery(_:) executes a raw SQL string over the Postgres simple query protocol — there are no parameter bindings available at all, so any tainted data in the SQL is SQL injection (CWE-89). Use `conn.query(PostgresQuery)` with string interpolation so values are sent as bound parameters.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// =========================================================================
		// Apple swift-cassandra-client (CassandraClient) — CQL injection (CWE-943)
		// =========================================================================
		//
		// https://github.com/apple/swift-cassandra-client is the official
		// Apple-maintained Cassandra/ScyllaDB driver for Swift, built on
		// SwiftNIO and used in Swift-on-server applications. It exposes three
		// CQL-string entry points, all of which take a raw CQL string as
		// arg 0:
		//
		//   1. cassandraClient.query("CQL...") / .run("CQL...") — top-level
		//      `CassandraClient` shortcut methods (lazy default session).
		//   2. session.query(...) / session.run(...) — same shape on a
		//      `CassandraSession` returned by `makeSession(keyspace:)` /
		//      `withSession(keyspace:) { session in … }`.
		//   3. Statement(query: "CQL...", parameters: […]) — explicit
		//      `Statement` constructor; the resulting Statement is then
		//      passed to `cassandraClient.execute(statement: …)`.
		//
		// String concatenation or `\(value)` interpolation into the CQL
		// argument is CQL injection (CWE-943). The safe pattern is `?`
		// placeholders bound via the `parameters: [Value]` list:
		//
		//   try Statement(query: "INSERT INTO t (a, b) VALUES (?, ?)",
		//                 parameters: [.string(name), .int32(age)])
		//   cassandraClient.query("SELECT * FROM t WHERE id = ?",
		//                         parameters: [.string(id)])
		//
		// Receiver matching: `cassandraClient` matches "CassandraClient" via
		// exact lowercase match (matcher.go:225); `cassandra` matches via the
		// HasPrefix(lastPart, lower) abbreviation rule (matcher.go:302);
		// `session`/`sess`/`s` match "CassandraSession" via the "session"
		// receiver heuristic (matcher.go:260-264). The `Statement(query:)`
		// constructor matches via the receiver-empty constructor rule
		// (matcher.go:210-216).

		{
			ID:            "swift.cassandra.cassandraclient.query",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `(?:cassandraClient|cassandra)\.query\s*\(`,
			ObjectType:    "CassandraClient",
			MethodName:    "query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Apple swift-cassandra-client CassandraClient.query(_:) executes its first argument as a raw CQL string. String concatenation or `\\(value)` interpolation of user-controlled data into arg 0 is CQL injection (CWE-943). Use `?` placeholders with `parameters: [Value]` — e.g. `cassandraClient.query(\"SELECT * FROM users WHERE id = ?\", parameters: [.string(id)])`.",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.cassandra.cassandraclient.run",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `(?:cassandraClient|cassandra)\.run\s*\(`,
			ObjectType:    "CassandraClient",
			MethodName:    "run",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Apple swift-cassandra-client CassandraClient.run(_:) executes its first argument as a raw CQL command (INSERT/UPDATE/DELETE/DDL). Tainted concatenation or interpolation into arg 0 is CQL injection (CWE-943). Use `?` placeholders with `parameters: [Value]` — e.g. `cassandraClient.run(\"INSERT INTO t (a) VALUES (?)\", parameters: [.string(name)])`.",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.cassandra.session.query",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `(?:session|sess)\.query\s*\(\s*"`,
			ObjectType:    "CassandraSession",
			MethodName:    "query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Apple swift-cassandra-client CassandraSession.query(_:) (the per-keyspace session returned by `makeSession(keyspace:)` / `withSession(keyspace:)`) executes arg 0 as a raw CQL string. Tainted concatenation or interpolation into arg 0 is CQL injection (CWE-943). Use `?` placeholders with `parameters: [Value]` to bind values safely.",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.cassandra.session.run",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `(?:session|sess)\.run\s*\(\s*"`,
			ObjectType:    "CassandraSession",
			MethodName:    "run",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Apple swift-cassandra-client CassandraSession.run(_:) (the per-keyspace session returned by `makeSession(keyspace:)` / `withSession(keyspace:)`) executes arg 0 as a raw CQL command. Tainted concatenation or interpolation into arg 0 is CQL injection (CWE-943). Use `?` placeholders with `parameters: [Value]` to bind values safely.",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.cassandra.statement.init",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `\bStatement\s*\(\s*query\s*:`,
			ObjectType:    "Statement",
			MethodName:    "Statement",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Apple swift-cassandra-client `Statement(query:parameters:options:)` constructor takes a raw CQL string as the `query:` argument. Tainted concatenation or interpolation into the `query:` string is CQL injection (CWE-943); the `parameters:` array is the safe binding mechanism. Build statements as `Statement(query: \"INSERT INTO t (a) VALUES (?)\", parameters: [.string(name)])` — never embed values into the CQL string.",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// Soto (AWS SDK for Swift) — query-language injection (CWE-943 / CWE-89)
		// https://github.com/soto-project/soto is the community-maintained,
		// production-grade Swift SDK for AWS, used by Vapor and other
		// server-side Swift apps. Several AWS data services accept a raw
		// query string (PartiQL / SQL / TimestreamQL) as the entry point of
		// the request input struct. String concatenation or `\(value)`
		// interpolation of user-controlled data into that query string is
		// query-language injection — DynamoDB executeStatement is the
		// canonical PartiQL-injection sink (DynamoDB's PartiQL evaluator
		// runs the supplied statement against the table; CWE-943), Athena
		// and RedshiftData are SQL (CWE-89), and TimestreamQuery is its
		// own SQL-like dialect (CWE-89 / CWE-943).
		//
		// The Soto call shape is:
		//
		//   let dynamoDB = DynamoDB(client: awsClient)
		//   try await dynamoDB.executeStatement(.init(statement: "<CQL>",
		//                                              parameters: [...]))
		//
		// Receiver matching (matcher.go): a variable named after the
		// service class (e.g. `dynamoDB`, `athena`, `redshiftData`,
		// `timestreamQuery`) lowercases to the same string as the
		// ObjectType's last component, so the exact-match arm fires.
		// Method names (`executeStatement`, `startQueryExecution`,
		// `executeTransaction`, `batchExecuteStatement`) are
		// service-distinctive — no other Swift library in the catalog
		// uses them — so even when scoping fails the FP risk is low.
		// The safe pattern across all four services is the structured
		// `parameters:` binding array (PartiQL/Redshift parameters,
		// Athena `executionParameters:`, Timestream `?` placeholders).

		{
			ID:            "swift.soto.dynamodb.executestatement",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `\bdynamo(?:DB|db|Db)\.executeStatement\s*\(`,
			ObjectType:    "DynamoDB",
			MethodName:    "executeStatement",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Soto SotoDynamoDB `DynamoDB.executeStatement(_:)` runs a PartiQL `statement:` string against the table. String concatenation or `\\(value)` interpolation into the `statement:` field of the `ExecuteStatementInput` is PartiQL injection (CWE-943) — DynamoDB's PartiQL evaluator treats the assembled string as a query plan. Use the `parameters: [DynamoDB.AttributeValue]` array — e.g. `dynamoDB.executeStatement(.init(statement: \"SELECT * FROM Users WHERE id = ?\", parameters: [.s(id)]))` — so values are bound rather than concatenated.",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.soto.dynamodb.executetransaction",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `\bdynamo(?:DB|db|Db)\.executeTransaction\s*\(`,
			ObjectType:    "DynamoDB",
			MethodName:    "executeTransaction",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Soto SotoDynamoDB `DynamoDB.executeTransaction(_:)` runs a list of `ParameterizedStatement` PartiQL statements atomically. Tainted concatenation or `\\(value)` interpolation into any `statement:` field inside `transactStatements:` is PartiQL injection (CWE-943); the `parameters:` array on each `ParameterizedStatement` is the safe binding mechanism. Build entries as `ParameterizedStatement(statement: \"UPDATE t SET v = ? WHERE id = ?\", parameters: [.s(v), .s(id)])`.",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.soto.dynamodb.batchexecutestatement",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangSwift,
			Pattern:       `\bdynamo(?:DB|db|Db)\.batchExecuteStatement\s*\(`,
			ObjectType:    "DynamoDB",
			MethodName:    "batchExecuteStatement",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Soto SotoDynamoDB `DynamoDB.batchExecuteStatement(_:)` runs an array of `BatchStatementRequest` PartiQL statements. Tainted concatenation or `\\(value)` interpolation into any `statement:` field of the `statements:` array is PartiQL injection (CWE-943). Use the per-request `parameters: [AttributeValue]` array — e.g. `BatchStatementRequest(parameters: [.s(id)], statement: \"SELECT * FROM Users WHERE id = ?\")`.",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.soto.athena.startqueryexecution",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `\bathena\.startQueryExecution\s*\(`,
			ObjectType:    "Athena",
			MethodName:    "startQueryExecution",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Soto SotoAthena `Athena.startQueryExecution(_:)` submits a `queryString:` (Presto/Trino-flavored SQL) to Amazon Athena for asynchronous execution. String concatenation or `\\(value)` interpolation into `queryString:` of the `StartQueryExecutionInput` is SQL injection (CWE-89). Use `?` placeholders with the `executionParameters: [String]` array — e.g. `athena.startQueryExecution(.init(queryString: \"SELECT * FROM logs WHERE user_id = ?\", executionParameters: [userID]))`.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.soto.redshiftdata.executestatement",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `\bredshift(?:Data|data)\.executeStatement\s*\(`,
			ObjectType:    "RedshiftData",
			MethodName:    "executeStatement",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Soto SotoRedshiftData `RedshiftData.executeStatement(_:)` runs a `sql:` string against an Amazon Redshift cluster via the Data API. String concatenation or `\\(value)` interpolation into `sql:` of the `ExecuteStatementInput` is SQL injection (CWE-89). Use the `parameters: [SqlParameter]` array with named placeholders — e.g. `redshiftData.executeStatement(.init(parameters: [.init(name: \"id\", value: id)], sql: \"SELECT * FROM users WHERE id = :id\", ...))`.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.soto.redshiftdata.batchexecutestatement",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `\bredshift(?:Data|data)\.batchExecuteStatement\s*\(`,
			ObjectType:    "RedshiftData",
			MethodName:    "batchExecuteStatement",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Soto SotoRedshiftData `RedshiftData.batchExecuteStatement(_:)` runs an array of `sqls: [String]` against an Amazon Redshift cluster. String concatenation or `\\(value)` interpolation into any element of `sqls:` is SQL injection (CWE-89). Build per-statement parameterized SQL via `executeStatement` with `parameters:` instead, or hard-code each batch element with no untrusted concatenation.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.soto.timestreamquery.query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `\btimestream(?:Query|query)\.query\s*\(`,
			ObjectType:    "TimestreamQuery",
			MethodName:    "query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Soto SotoTimestreamQuery `TimestreamQuery.query(_:)` runs a `queryString:` against Amazon Timestream's SQL-like query engine. String concatenation or `\\(value)` interpolation into `queryString:` of the `QueryInput` is SQL injection (CWE-89). Timestream supports prepared queries via `?` placeholders — bind values rather than concatenating them into the queryString.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// ── Firebase iOS SDK — Firestore document/collection path injection (CWE-639) ───
		// Firestore.document(_:), .collection(_:), .collectionGroup(_:) accept absolute
		// slash-separated path strings. When user-controlled data is interpolated into
		// these paths (e.g. `db.document("users/\(userId)/private")`), an attacker can
		// pivot across documents/collections, bypassing per-document security rules and
		// reaching data they should not see (NoSQL access-control bypass / IDOR class).
		// Use a constant top-level path with the user value bound only as a leaf segment
		// after authorization, or rely on `whereField(_:isEqualTo:)` queries scoped by
		// `request.auth.uid` in security rules.
		{
			ID:            "swift.firebase.firestore.document",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `(?:Firestore\.firestore\(\)|firestore)\.document\s*\(\s*"`,
			ObjectType:    "Firestore",
			MethodName:    "document",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Firebase Firestore `Firestore.document(_:)` resolves an absolute slash-separated document path. Tainted concatenation or `\\(value)` interpolation into the path is access-control bypass / NoSQL path injection (CWE-639) — combined with permissive rules an attacker reads/writes arbitrary documents. Pin path prefixes to constants and validate user IDs against the authenticated principal before use.",
			CWEID:         "CWE-639",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.firebase.firestore.collection",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `(?:Firestore\.firestore\(\)|firestore)\.collection\s*\(\s*"`,
			ObjectType:    "Firestore",
			MethodName:    "collection",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Firebase Firestore `Firestore.collection(_:)` resolves a collection path. Tainted interpolation into the collection path lets an attacker pivot to arbitrary top-level or sub-collections (CWE-639), bypassing per-collection security rules. Use a fixed collection name and pass user input only via `.document(...)` after authorization checks.",
			CWEID:         "CWE-639",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.firebase.firestore.collectiongroup",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `(?:Firestore\.firestore\(\)|firestore)\.collectionGroup\s*\(\s*"`,
			ObjectType:    "Firestore",
			MethodName:    "collectionGroup",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Firebase Firestore `Firestore.collectionGroup(_:)` queries every collection with the given identifier across the entire database, bypassing parent-document scoping. Tainted interpolation into the group ID lets an attacker target collections they have no parent path to (CWE-639). Hard-code the collection group identifier and rely on security rules with `request.auth.uid` checks.",
			CWEID:         "CWE-639",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// ── Firebase iOS SDK — Realtime Database path injection (CWE-639) ────────────
		// Realtime Database addressing is path-based: `Database.database().reference(withPath:)`
		// and `DatabaseReference.child(_:)` both accept a slash-separated path. When user
		// data is interpolated into these paths (e.g. `ref.child("users/\(uid)/secrets")`),
		// an attacker can read or overwrite arbitrary nodes in the JSON tree, bypassing
		// per-path security rules. Use constant path prefixes and validate user-supplied
		// segments against the authenticated principal before constructing the reference.
		{
			ID:            "swift.firebase.rtdb.reference.withpath",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `(?:Database\.database\(\)|database)\.reference\s*\(\s*withPath:`,
			ObjectType:    "Database",
			MethodName:    "reference",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Firebase Realtime Database `Database.reference(withPath:)` resolves an absolute path in the JSON tree. Tainted interpolation into the path is access-control bypass (CWE-639) — combined with permissive rules an attacker reads/writes arbitrary nodes. Pin path prefixes to constants and rely on `auth.uid`-scoped security rules instead of client-supplied paths.",
			CWEID:         "CWE-639",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.firebase.rtdb.child",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangSwift,
			Pattern:       `(?:databaseReference|dbReference|rtdbRef)\.child\s*\(\s*"`,
			ObjectType:    "DatabaseReference",
			MethodName:    "child",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Firebase Realtime Database `DatabaseReference.child(_:)` appends a tainted path segment to the parent reference. Slash-separated user input lets an attacker traverse upward (`../../`-style is rejected, but `users/<other-uid>/...` segments succeed), bypassing per-path security rules (CWE-639). Constrain user input to a single non-slash segment (use `.contains(\"/\")` rejection) and depend on `auth.uid`-scoped rules.",
			CWEID:         "CWE-639",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// ── Firebase iOS SDK — Cloud Storage SSRF / path injection ──────────────────
		// `Storage.storage().reference(forURL:)` accepts a `gs://` or `https://` URL and
		// returns a StorageReference for any bucket the URL points to. A user-controlled
		// URL string can redirect the client to an attacker-owned bucket (data exfiltration
		// via subsequent puts) or to internal Firebase storage objects the user shouldn't
		// see (CWE-918). Pair with `.child(_:)` path injection below.
		{
			ID:            "swift.firebase.storage.reference.forurl",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `(?:Storage\.storage\(\)|storage)\.reference\s*\(\s*forURL:`,
			ObjectType:    "Storage",
			MethodName:    "reference",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Firebase Cloud Storage `Storage.reference(forURL:)` accepts a `gs://bucket/path` or `https://firebasestorage.googleapis.com/...` URL. A tainted URL pivots the StorageReference to an attacker-chosen bucket, leading to SSRF-style data leak or write-to-attacker-bucket on subsequent operations (CWE-918). Validate the URL's bucket against an allow-list before constructing the reference.",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery (SSRF)",
		},
		{
			ID:            "swift.firebase.storage.child",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `(?:storageReference|storageRef|stRef)\.child\s*\(\s*"`,
			ObjectType:    "StorageReference",
			MethodName:    "child",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Firebase Cloud Storage `StorageReference.child(_:)` appends a slash-separated path under the parent storage object. Tainted interpolation lets an attacker overwrite or read sibling/private objects in the same bucket, bypassing per-prefix security rules (CWE-22 / CWE-639). Constrain user input to a single non-slash filename and pin the directory prefix as a constant.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// ── Firebase iOS SDK — Cloud Messaging topic subscription (CWE-501) ──────────
		// `Messaging.messaging().subscribe(toTopic:)` subscribes the device to a named
		// topic; subsequent server-broadcast messages on that topic are delivered.
		// User-controlled topic names let attackers influence which messages a device
		// receives (e.g. arbitrary admin-broadcast topics, cross-tenant topic mixing),
		// crossing the trust boundary between client-supplied data and FCM topic ACLs.
		{
			ID:            "swift.firebase.messaging.subscribe",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangSwift,
			Pattern:       `(?:Messaging\.messaging\(\)|messaging)\.subscribe\s*\(\s*toTopic:`,
			ObjectType:    "Messaging",
			MethodName:    "subscribe",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Firebase Cloud Messaging `Messaging.subscribe(toTopic:)` enrolls the device in a named broadcast topic. Tainted topic names let an attacker subscribe the device to admin/cross-tenant topics whose payloads they would not otherwise receive, crossing a trust boundary between client input and FCM topic ACLs (CWE-501). Constrain topic names to an allow-list of business-defined values rather than passing user input directly.",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},

		// ── Vapor Client (req.client / app.client) outbound HTTP — SSRF (CWE-918) ──
		// `Client` is Vapor's outbound HTTP client protocol, accessed in handlers via
		// `req.client` and at app scope via `app.client`. The verb methods take a
		// `URI` (typically built from a `String`) as arg 0; `send(_:)` takes a
		// `ClientRequest` whose URI was set from a string. A tainted URL → SSRF:
		// internal-network reachability, cloud-metadata endpoints (169.254.169.254),
		// localhost-only admin services. Existing AsyncHTTPClient.shared / Alamofire
		// entries do NOT cover Vapor's `Client` protocol — different ObjectType.
		// ObjectType "Vapor.Client" matches receivers `client`, `req.client`,
		// `app.client` via tsflow matcher.go's lastPart/recvLast heuristic
		// (typeParts ["Vapor","Client"] → lastPart "client" → matches receiver whose
		// last dot-segment is "client"). Methods get/post/put/delete/patch/send all
		// take the URL/URI as arg 0. Mitigation: validate URL host against an
		// allow-list before constructing the URI.
		{
			ID:            "swift.vapor.client.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `\.client\.(?:get|post|put|delete|patch|send)\s*\(`,
			ObjectType:    "Vapor.Client",
			MethodName:    "get/post/put/delete/patch/send",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Vapor `Client` outbound HTTP method (req.client.get/post/put/delete/patch/send or app.client.*) with potentially tainted URL/URI. A user-controlled URL lets an attacker pivot the server's HTTP egress to internal-network targets, cloud-metadata endpoints (169.254.169.254), or localhost-only admin services (CWE-918, SSRF). Validate the URL's host against a static allow-list before constructing the URI.",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery (SSRF)",
		},

		// ── AsyncHTTPClient instance convenience methods — SSRF (CWE-918) ──
		// AsyncHTTPClient (`HTTPClient` from swift-server/async-http-client) exposes
		// `get(url:)`, `post(url:)`, `put(url:)`, `delete(url:)`, `patch(url:)`,
		// `head(url:)` convenience methods on instances (in addition to `execute(_:)`).
		// The existing `swift.asynchttp.shared.get` covers ONLY the
		// `HTTPClient.shared` singleton path; instance usage like
		// `let client = HTTPClient(eventLoopGroupProvider: .singleton); client.get(url:)`
		// previously had no sink coverage. ObjectType "HTTPClient" matches receivers
		// `httpClient`, `client` whose lower-cased last dot-segment equals
		// "httpclient" — receiver `client` alone won't match HTTPClient's lastPart
		// "httpclient" (different lastPart from Vapor's "client"), so the two
		// entries don't overlap. Receiver `httpClient` is the canonical idiom in
		// async-http-client docs.
		{
			ID:            "swift.asynchttp.client.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `httpClient\.(?:get|post|put|delete|patch|head)\s*\(\s*url:`,
			ObjectType:    "HTTPClient",
			MethodName:    "httpClient.get/httpClient.post/httpClient.put/httpClient.delete/httpClient.patch/httpClient.head",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "AsyncHTTPClient (`HTTPClient` from swift-server/async-http-client) instance convenience method `httpClient.get(url:)` / `.post(url:)` / `.put(url:)` / `.delete(url:)` / `.patch(url:)` / `.head(url:)` with potentially tainted URL string. A tainted URL lets an attacker pivot the server's outbound HTTP fetch to internal-network targets or cloud-metadata endpoints (CWE-918, SSRF). Validate the host against a static allow-list before passing.",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery (SSRF)",
		},

		// ── Vapor WebSocket.connect outbound — SSRF (CWE-918) ──
		// `WebSocket.connect(to:on:onUpgrade:)` (and its `headers:` variant) is the
		// canonical static method for opening an outbound WebSocket from Vapor /
		// SwiftNIO. Arg 0 (`to:`) is the target URL string. A user-controlled URL
		// lets an attacker pivot the server's outbound WebSocket connection to
		// internal services or cloud-metadata. Existing `swift.vapor.websocket.send`
		// covers OUTBOUND DATA over an established socket; this covers the URL of
		// the outbound CONNECT itself. ObjectType "WebSocket" matches receiver
		// "WebSocket" (static class call) directly via lastPart equality.
		{
			ID:            "swift.vapor.websocket.connect",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `WebSocket\.connect\s*\(\s*to:`,
			ObjectType:    "WebSocket",
			MethodName:    "connect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Vapor / SwiftNIO `WebSocket.connect(to:on:onUpgrade:)` opens an outbound WebSocket to the given URL string (arg 0). A tainted URL lets an attacker pivot the server's WebSocket egress to internal-network targets, localhost-only admin services, or cloud-metadata endpoints (CWE-918, SSRF). Validate the URL's host against a static allow-list before connecting.",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery (SSRF)",
		},

		// ──────────────────────────────────────────────────────────────────
		// SSH / SFTP remote operations — Citadel, Shout, NMSSH (CWE-78/22/918)
		// ──────────────────────────────────────────────────────────────────
		// Server-side Swift has three commonly-used SSH stacks: Citadel
		// (orlandos-nl/Citadel, pure-Swift on swift-nio-ssh), Shout
		// (jakeheis/Shout, libssh2 wrapper), and NMSSH (NMSSH/NMSSH, libssh2
		// ObjC bridge). Until now Swift was the only tsflow language with no
		// SSH/SFTP coverage. A user-controlled value reaching a remote command
		// (`executeCommand` / `ssh.execute`) is CWE-78; a user-controlled path
		// reaching an SFTP file op is CWE-22 path traversal on the remote host;
		// a user-controlled hostname reaching the connect call is CWE-918 SSRF
		// (the server is steered into opening an SSH session to an attacker's
		// host). Mitigation: never interpolate untrusted data into the remote
		// command; validate SFTP paths against a fixed root; pin the SSH host
		// to a static allow-list.

		// ── Citadel — remote command execution (CWE-78) ──
		// `let stdout = try await client.executeCommand("ls -la \(dir)")` runs
		// the string on the remote shell. `executeCommandStream` is the
		// streaming variant. ObjectType is empty because the canonical Citadel
		// idiom names the client `client` (the README example) — which the
		// tsflow receiver heuristic cannot abbreviate to `SSHClient`; the
		// compound method name `executeCommand` is distinctive enough on its
		// own (mirrors the empty-ObjectType `swift.system` / `swift.popen`
		// entries above).
		{
			ID:            "swift.citadel.executecommand",
			Category:      taint.SnkCommand,
			Language:      rules.LangSwift,
			Pattern:       `\.executeCommand(?:Stream)?\s*\(`,
			ObjectType:    "",
			MethodName:    "executeCommand/executeCommandStream",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Citadel SSH client `client.executeCommand(_:)` / `executeCommandStream(_:)` runs the given string on the remote shell. Interpolating untrusted input here is OS command injection on the remote host (CWE-78). Build the argument vector from constants only; never concatenate user input into the command string.",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// ── Shout — remote command execution (CWE-78) ──
		// `ssh.execute("apt-get install \(pkg)")` / `ssh.capture("cat \(path)")`
		// run on the remote shell. ObjectType "SSH" matches the canonical
		// receiver `ssh` (and its prefixes) — Shout's class is literally `SSH`.
		{
			ID:            "swift.shout.ssh.execute",
			Category:      taint.SnkCommand,
			Language:      rules.LangSwift,
			Pattern:       `\bssh\.(?:execute|capture)\s*\(`,
			ObjectType:    "SSH",
			MethodName:    "execute/capture",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Shout SSH session `ssh.execute(_:)` / `ssh.capture(_:)` runs the given string on the remote shell. Interpolating untrusted input here is OS command injection on the remote host (CWE-78). Never concatenate user input into the command string.",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// ── SSH connect to a user-controlled host (CWE-918 SSRF) ──
		// Citadel: `SSHClient.connect(host: target, authenticationMethod: …)`.
		// ObjectType "SSHClient" matches the static-call receiver `SSHClient`
		// (and abbreviations like `ssh`).
		{
			ID:            "swift.citadel.sshclient.connect",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `SSHClient\.connect\s*\(`,
			ObjectType:    "SSHClient",
			MethodName:    "connect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Citadel `SSHClient.connect(host:…)` opens an SSH session to the given host (arg 0). A user-controlled hostname lets an attacker steer the server into connecting to an internal or attacker-owned host (CWE-918, SSRF-style). Pin the host to a static allow-list.",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery (SSRF)",
		},
		// Shout: `SSH(host: target)` or `SSH.connect(host: target) { ssh in … }`.
		// ObjectType "SSH" matches the constructor call and the static
		// `SSH.connect`; arg 0 is the host in both forms.
		{
			ID:            "swift.shout.ssh.connect",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `\bSSH\.connect\s*\(\s*host:|\bSSH\s*\(\s*host:`,
			ObjectType:    "SSH",
			MethodName:    "connect/SSH",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Shout `SSH(host:)` / `SSH.connect(host:)` opens an SSH session to the given host (arg 0). A user-controlled hostname lets an attacker steer the server into connecting to an internal or attacker-owned host (CWE-918, SSRF-style). Pin the host to a static allow-list.",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery (SSRF)",
		},
		// NMSSH: `NMSSHSession.connect(toHost: target, withUsername: …)` or
		// `NMSSHSession(host: target, andUsername: …)`. ObjectType
		// "NMSSHSession" matches the static-call and constructor receiver
		// exactly; arg 0 is the host in both forms.
		{
			ID:            "swift.nmssh.session.connect",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangSwift,
			Pattern:       `NMSSHSession\.connect\s*\(\s*toHost:|NMSSHSession\s*\(\s*host:`,
			ObjectType:    "NMSSHSession",
			MethodName:    "connect/NMSSHSession",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "NMSSH `NMSSHSession.connect(toHost:…)` / `NMSSHSession(host:…)` opens an SSH session to the given host (arg 0). A user-controlled hostname lets an attacker steer the server into connecting to an internal or attacker-owned host (CWE-918, SSRF-style). Pin the host to a static allow-list.",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery (SSRF)",
		},

		// ── SFTP file operations with a user-controlled remote path (CWE-22) ──
		// Citadel SFTPClient methods are all reached via a `sftp` receiver
		// (`let sftp = try await client.openSFTP()`). ObjectType "SFTPClient"
		// matches the `sftp` receiver via the tsflow abbreviation heuristic and
		// also matches NMSSH's `session.sftp.…` chained receiver (recvLast
		// "sftp"). `openFile` / `withFile` take the remote path as `filePath:`
		// (arg 0); the rest take `atPath:` / `at:` (arg 0).
		{
			ID:            "swift.sftp.openfile",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `\bsftp\.(?:openFile|withFile)\s*\(`,
			ObjectType:    "SFTPClient",
			MethodName:    "openFile/withFile",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SFTP `sftp.openFile(filePath:flags:)` / `withFile(filePath:flags:_:)` opens a file on the remote host at the given path. A user-controlled path (e.g. `\"/data/\\(name)\"`) lets an attacker read or overwrite arbitrary files on the remote host via `../` traversal (CWE-22). Resolve the path against a fixed root and reject `..` segments before opening.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.sftp.listdirectory",
			Category:      taint.SnkFileRead,
			Language:      rules.LangSwift,
			Pattern:       `\bsftp\.listDirectory\s*\(`,
			ObjectType:    "SFTPClient",
			MethodName:    "listDirectory",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SFTP `sftp.listDirectory(atPath:)` lists a directory on the remote host. A user-controlled path lets an attacker enumerate arbitrary remote directories via `../` traversal (CWE-22). Resolve the path against a fixed root before listing.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.sftp.createdirectory",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `\bsftp\.createDirectory\s*\(`,
			ObjectType:    "SFTPClient",
			MethodName:    "createDirectory",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SFTP `sftp.createDirectory(atPath:)` (Citadel / Shout) creates a directory on the remote host. A user-controlled path lets an attacker create directories at arbitrary remote locations via `../` traversal (CWE-22). Resolve the path against a fixed root first.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.sftp.removepath",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `\bsftp\.(?:rmdir|removeFile|removeDirectory)\s*\(`,
			ObjectType:    "SFTPClient",
			MethodName:    "rmdir/removeFile/removeDirectory",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SFTP `sftp.rmdir(at:)` (Citadel) / `removeFile(_:)` / `removeDirectory(_:)` (Shout) deletes a file or directory on the remote host. A user-controlled path lets an attacker delete arbitrary remote files via `../` traversal (CWE-22). Resolve the path against a fixed root before deleting.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.sftp.rename",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `\bsftp\.rename\s*\(`,
			ObjectType:    "SFTPClient",
			MethodName:    "rename",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "SFTP `sftp.rename(at:to:)` (Citadel) / `rename(src:dest:)` (Shout) moves a file on the remote host. User-controlled source or destination paths let an attacker read/clobber arbitrary remote files via `../` traversal (CWE-22). Resolve both paths against a fixed root before renaming.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		// Shout-specific SFTP transfer methods (`let sftp = try ssh.openSftp()`).
		// ObjectType "SFTP" is Shout's class name and matches the `sftp`
		// receiver. `upload(localURL:remotePath:)` and
		// `download(remotePath:localURL:)` both take a local path and a remote
		// path — either being attacker-controlled is a traversal hazard, so
		// both args are flagged. `listFiles(in:)` takes the remote directory.
		{
			ID:            "swift.sftp.listfiles",
			Category:      taint.SnkFileRead,
			Language:      rules.LangSwift,
			Pattern:       `\bsftp\.listFiles\s*\(`,
			ObjectType:    "SFTP",
			MethodName:    "listFiles",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Shout SFTP `sftp.listFiles(in:)` lists a directory on the remote host. A user-controlled path lets an attacker enumerate arbitrary remote directories via `../` traversal (CWE-22). Resolve the path against a fixed root before listing.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.sftp.upload",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `\bsftp\.upload\s*\(`,
			ObjectType:    "SFTP",
			MethodName:    "upload",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Shout SFTP `sftp.upload(localURL:remotePath:)` writes a local file to the remote host. A user-controlled remote path lets an attacker plant a file at an arbitrary remote location (e.g. a webroot) via `../` traversal; a user-controlled local path lets them exfiltrate arbitrary local files (CWE-22). Resolve both paths against fixed roots before uploading.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "swift.sftp.download",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangSwift,
			Pattern:       `\bsftp\.download\s*\(`,
			ObjectType:    "SFTP",
			MethodName:    "download",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Shout SFTP `sftp.download(remotePath:localURL:)` reads a remote file and writes it locally. A user-controlled remote path lets an attacker read arbitrary remote files; a user-controlled local path lets them overwrite arbitrary local files via `../` traversal (CWE-22). Resolve both paths against fixed roots before downloading.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- File-upload sinks (CWE-434) ---
		// Vapor's NIO-backed file I/O persists request bodies. A tainted
		// destination path (or accepting the upload without an extension /
		// MIME allowlist) is unrestricted file upload.
		{
			ID:            "swift.vapor.fileio.writefile",
			Category:      taint.SnkUpload,
			Language:      rules.LangSwift,
			Pattern:       `\.writeFile\s*\(`,
			ObjectType:    "FileIO",
			MethodName:    "writeFile",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "Vapor `request.fileio.writeFile(buffer, at: path)` persists request bytes at the given path; a tainted path is path traversal + unrestricted file upload (CWE-434).",
			CWEID:         "CWE-434",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "swift.vapor.file.filename",
			Category:      taint.SnkUpload,
			Language:      rules.LangSwift,
			Pattern:       `\.filename\b`,
			ObjectType:    "Vapor.File",
			MethodName:    "filename",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Vapor `File.filename` — client-supplied uploaded filename. Reusing it as a destination component is path traversal + unrestricted upload (CWE-434).",
			CWEID:         "CWE-434",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "swift.vapor.request.body.collect",
			Category:      taint.SnkUpload,
			Language:      rules.LangSwift,
			Pattern:       `\.body\.collect\s*\(`,
			ObjectType:    "Vapor.Request",
			MethodName:    "body.collect",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Vapor `request.body.collect()` gathers the full request body; downstream `FileIO.writeFile(at:)` with a tainted path is unrestricted file upload (CWE-434).",
			CWEID:         "CWE-434",
			OWASPCategory: "A04:2021-Insecure Design",
		},

		// --- CSV/formula injection sinks (CWE-1236) ---
		{
			ID:            "swift.codablecsv.writer.write",
			Category:      taint.SnkCSV,
			Language:      rules.LangSwift,
			Pattern:       `\.write\s*\(\s*row\s*:`,
			ObjectType:    "CSVWriter",
			MethodName:    "write",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "CodableCSV CSVWriter.write(row:) — string cells starting with =, +, -, @, tab, or CR become spreadsheet formulas when opened in Excel/Sheets (CSV/formula injection, CWE-1236). Sanitize at-risk cells with a leading single quote.",
			CWEID:         "CWE-1236",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "swift.swiftcsv.append",
			Category:      taint.SnkCSV,
			Language:      rules.LangSwift,
			Pattern:       `\.append\s*\(\s*row\s*:|\.appendRow\s*\(`,
			ObjectType:    "SwiftCSV",
			MethodName:    "append",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "SwiftCSV row append — tainted cell prefixes (= + - @ tab CR) cause spreadsheet formula injection (CWE-1236).",
			CWEID:         "CWE-1236",
			OWASPCategory: "A03:2021-Injection",
		},
	}
}
