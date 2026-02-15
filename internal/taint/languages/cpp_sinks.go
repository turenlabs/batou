package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

func (cppCatalog) Sinks() []taint.SinkDef {
	return []taint.SinkDef{
		// ── Command injection (C-inherited + C++) ────────────────────
		{ID: "cpp.system", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bsystem\s*\(`, ObjectType: "", MethodName: "system", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via system()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "cpp.popen", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bpopen\s*\(`, ObjectType: "", MethodName: "popen", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via popen()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "cpp.exec", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bexecl[pe]?\s*\(|\bexecv[pe]?\s*\(`, ObjectType: "", MethodName: "exec*", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via exec family", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

		// ── Format string vulnerabilities ─────────────────────────────
		{ID: "cpp.printf.format", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bprintf\s*\(\s*\w`, ObjectType: "", MethodName: "printf", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "printf with user-controlled format string", CWEID: "CWE-134", OWASPCategory: "A03:2021-Injection"},
		{ID: "cpp.sprintf.format", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bsprintf\s*\(`, ObjectType: "", MethodName: "sprintf", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "sprintf with potential buffer overflow and format string", CWEID: "CWE-134", OWASPCategory: "A03:2021-Injection"},
		{ID: "cpp.fprintf.format", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bfprintf\s*\(`, ObjectType: "", MethodName: "fprintf", DangerousArgs: []int{1}, Severity: rules.High, Description: "fprintf with user-controlled format string", CWEID: "CWE-134", OWASPCategory: "A03:2021-Injection"},
		{ID: "cpp.snprintf.format", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bsnprintf\s*\(`, ObjectType: "", MethodName: "snprintf", DangerousArgs: []int{2}, Severity: rules.High, Description: "snprintf with user-controlled format string", CWEID: "CWE-134", OWASPCategory: "A03:2021-Injection"},
		{ID: "cpp.syslog.format", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bsyslog\s*\(`, ObjectType: "", MethodName: "syslog", DangerousArgs: []int{1}, Severity: rules.High, Description: "syslog with user-controlled format string", CWEID: "CWE-134", OWASPCategory: "A03:2021-Injection"},

		// ── Buffer overflow sinks (C-inherited) ──────────────────────
		{ID: "cpp.strcpy", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bstrcpy\s*\(`, ObjectType: "", MethodName: "strcpy", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "strcpy with no bounds checking (buffer overflow)", CWEID: "CWE-120", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},
		{ID: "cpp.strcat", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bstrcat\s*\(`, ObjectType: "", MethodName: "strcat", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "strcat with no bounds checking (buffer overflow)", CWEID: "CWE-120", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},
		{ID: "cpp.memcpy", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bmemcpy\s*\(`, ObjectType: "", MethodName: "memcpy", DangerousArgs: []int{1, 2}, Severity: rules.High, Description: "memcpy with tainted source or size (buffer overflow)", CWEID: "CWE-120", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},
		{ID: "cpp.memmove", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bmemmove\s*\(`, ObjectType: "", MethodName: "memmove", DangerousArgs: []int{1, 2}, Severity: rules.High, Description: "memmove with tainted source or size", CWEID: "CWE-120", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},

		// ── File operations ───────────────────────────────────────────
		{ID: "cpp.fopen", Category: taint.SnkFileWrite, Language: rules.LangCPP, Pattern: `\bfopen\s*\(`, ObjectType: "", MethodName: "fopen", DangerousArgs: []int{0}, Severity: rules.High, Description: "File open with user-controlled path (path traversal)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "cpp.ofstream", Category: taint.SnkFileWrite, Language: rules.LangCPP, Pattern: `(?:std::)?ofstream\s+\w+\s*\(`, ObjectType: "std::ofstream", MethodName: "ofstream", DangerousArgs: []int{0}, Severity: rules.High, Description: "Output file stream with user-controlled path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "cpp.fstream.open", Category: taint.SnkFileWrite, Language: rules.LangCPP, Pattern: `\.open\s*\(`, ObjectType: "std::fstream", MethodName: "open", DangerousArgs: []int{0}, Severity: rules.High, Description: "File stream open with user-controlled path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "cpp.posix.open", Category: taint.SnkFileWrite, Language: rules.LangCPP, Pattern: `\bopen\s*\(\s*[^)]*,\s*O_`, ObjectType: "", MethodName: "open", DangerousArgs: []int{0}, Severity: rules.High, Description: "POSIX open with user-controlled path (path traversal)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "cpp.access", Category: taint.SnkFileWrite, Language: rules.LangCPP, Pattern: `\baccess\s*\(`, ObjectType: "", MethodName: "access", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "File access check with user-controlled path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "cpp.remove", Category: taint.SnkFileWrite, Language: rules.LangCPP, Pattern: `\bremove\s*\(`, ObjectType: "", MethodName: "remove", DangerousArgs: []int{0}, Severity: rules.High, Description: "File removal with user-controlled path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "cpp.rename", Category: taint.SnkFileWrite, Language: rules.LangCPP, Pattern: `\brename\s*\(`, ObjectType: "", MethodName: "rename", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "File rename with user-controlled path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "cpp.unlink", Category: taint.SnkFileWrite, Language: rules.LangCPP, Pattern: `\bunlink\s*\(`, ObjectType: "", MethodName: "unlink", DangerousArgs: []int{0}, Severity: rules.High, Description: "File unlink with user-controlled path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "cpp.mkdir", Category: taint.SnkFileWrite, Language: rules.LangCPP, Pattern: `\bmkdir\s*\(`, ObjectType: "", MethodName: "mkdir", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Directory creation with user-controlled path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// ── SQL injection ─────────────────────────────────────────────
		{ID: "cpp.sql.exec", Category: taint.SnkSQLQuery, Language: rules.LangCPP, Pattern: `(?:sqlite3_exec|mysql_query|mysql_real_query|PQexec|PQexecParams)\s*\(`, ObjectType: "", MethodName: "sql_exec", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "SQL query execution with potential injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "cpp.sql.prepare", Category: taint.SnkSQLQuery, Language: rules.LangCPP, Pattern: `(?:sqlite3_prepare|sqlite3_prepare_v2|mysql_stmt_prepare)\s*\(`, ObjectType: "", MethodName: "sql_prepare", DangerousArgs: []int{1}, Severity: rules.High, Description: "SQL statement preparation with tainted string", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// ── c_str() passed to C functions (string bridge) ─────────────
		{ID: "cpp.cstr.to.cfunc", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\.c_str\s*\(\s*\)`, ObjectType: "std::string", MethodName: "c_str", DangerousArgs: []int{-1}, Severity: rules.Medium, Description: "std::string::c_str() passed to C function (loses C++ safety)", CWEID: "CWE-676", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},

		// ── STL unchecked access ──────────────────────────────────────
		{ID: "cpp.stl.operator.bracket", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\[\s*\w+\s*\]`, ObjectType: "container", MethodName: "operator[]", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Unchecked container access via operator[] with tainted index", CWEID: "CWE-125", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},
		{ID: "cpp.stl.front.empty", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\.front\s*\(\s*\)`, ObjectType: "container", MethodName: "front", DangerousArgs: []int{-1}, Severity: rules.Medium, Description: "Container .front() on potentially empty container", CWEID: "CWE-125", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},
		{ID: "cpp.stl.back.empty", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\.back\s*\(\s*\)`, ObjectType: "container", MethodName: "back", DangerousArgs: []int{-1}, Severity: rules.Medium, Description: "Container .back() on potentially empty container", CWEID: "CWE-125", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},

		// ── Memory management sinks ───────────────────────────────────
		{ID: "cpp.new.array.raw", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bnew\s+\w+\s*\[`, ObjectType: "", MethodName: "new[]", DangerousArgs: []int{0}, Severity: rules.High, Description: "Raw new[] allocation with tainted size (integer overflow/OOM)", CWEID: "CWE-190", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},
		{ID: "cpp.malloc.tainted.size", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bmalloc\s*\(`, ObjectType: "", MethodName: "malloc", DangerousArgs: []int{0}, Severity: rules.High, Description: "malloc with tainted size argument", CWEID: "CWE-190", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},
		{ID: "cpp.realloc.tainted.size", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\brealloc\s*\(`, ObjectType: "", MethodName: "realloc", DangerousArgs: []int{1}, Severity: rules.High, Description: "realloc with tainted size argument", CWEID: "CWE-190", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},
		{ID: "cpp.calloc.tainted.size", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bcalloc\s*\(`, ObjectType: "", MethodName: "calloc", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "calloc with tainted count or size argument", CWEID: "CWE-190", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},
		{ID: "cpp.alloca.tainted.size", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\balloca\s*\(`, ObjectType: "", MethodName: "alloca", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "alloca with tainted size on stack (stack overflow)", CWEID: "CWE-190", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},

		// ── Smart pointer misuse ──────────────────────────────────────
		{ID: "cpp.unique_ptr.get", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\.get\s*\(\s*\)`, ObjectType: "std::unique_ptr", MethodName: "get", DangerousArgs: []int{-1}, Severity: rules.Medium, Description: "unique_ptr::get() extracts raw pointer, bypassing ownership", CWEID: "CWE-416", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},
		{ID: "cpp.unique_ptr.release", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\.release\s*\(\s*\)`, ObjectType: "std::unique_ptr", MethodName: "release", DangerousArgs: []int{-1}, Severity: rules.Medium, Description: "unique_ptr::release() gives up ownership, must be manually freed", CWEID: "CWE-401", OWASPCategory: "A06:2021-Vulnerable and Outdated Components"},

		// ── Deserialization sinks ──────────────────────────────────────
		{ID: "cpp.boost.serialization.input", Category: taint.SnkDeserialize, Language: rules.LangCPP, Pattern: `boost::archive::\w+_iarchive\s+\w+\s*\(`, ObjectType: "boost::archive", MethodName: "input_archive", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Boost.Serialization deserialization from untrusted input", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
		{ID: "cpp.protobuf.parse.untrusted", Category: taint.SnkDeserialize, Language: rules.LangCPP, Pattern: `\.ParseFromString\s*\(|\.ParseFromArray\s*\(|\.ParseFromIstream\s*\(`, ObjectType: "google::protobuf::Message", MethodName: "ParseFrom*", DangerousArgs: []int{0}, Severity: rules.High, Description: "Protocol Buffers parsing from untrusted input", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

		// ── Template / format injection ────────────────────────────────
		{ID: "cpp.fmt.format.tainted", Category: taint.SnkTemplate, Language: rules.LangCPP, Pattern: `fmt::format\s*\(`, ObjectType: "fmt", MethodName: "format", DangerousArgs: []int{0}, Severity: rules.High, Description: "fmt::format with user-controlled format string", CWEID: "CWE-134", OWASPCategory: "A03:2021-Injection"},
		{ID: "cpp.std.format.tainted", Category: taint.SnkTemplate, Language: rules.LangCPP, Pattern: `std::format\s*\(`, ObjectType: "std", MethodName: "format", DangerousArgs: []int{0}, Severity: rules.High, Description: "std::format (C++20) with user-controlled format string", CWEID: "CWE-134", OWASPCategory: "A03:2021-Injection"},

		// ── Log injection ─────────────────────────────────────────────
		{ID: "cpp.spdlog.info", Category: taint.SnkLog, Language: rules.LangCPP, Pattern: `spdlog::info\s*\(`, ObjectType: "spdlog", MethodName: "info", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "spdlog info with tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "cpp.spdlog.error", Category: taint.SnkLog, Language: rules.LangCPP, Pattern: `spdlog::error\s*\(`, ObjectType: "spdlog", MethodName: "error", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "spdlog error with tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "cpp.spdlog.warn", Category: taint.SnkLog, Language: rules.LangCPP, Pattern: `spdlog::warn\s*\(`, ObjectType: "spdlog", MethodName: "warn", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "spdlog warn with tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "cpp.cout.tainted", Category: taint.SnkLog, Language: rules.LangCPP, Pattern: `std::cout\s*<<`, ObjectType: "std::ostream", MethodName: "operator<<", DangerousArgs: []int{0}, Severity: rules.Low, Description: "std::cout output with tainted data", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "cpp.cerr.tainted", Category: taint.SnkLog, Language: rules.LangCPP, Pattern: `std::cerr\s*<<`, ObjectType: "std::ostream", MethodName: "operator<<", DangerousArgs: []int{0}, Severity: rules.Low, Description: "std::cerr output with tainted data", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},

		// ── Network sinks / SSRF ──────────────────────────────────────
		{ID: "cpp.curl.setopt.url", Category: taint.SnkURLFetch, Language: rules.LangCPP, Pattern: `curl_easy_setopt\s*\([^,]+,\s*CURLOPT_URL`, ObjectType: "CURL", MethodName: "curl_easy_setopt(CURLOPT_URL)", DangerousArgs: []int{2}, Severity: rules.High, Description: "libcurl URL set with user-controlled address (SSRF)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "cpp.socket.connect", Category: taint.SnkURLFetch, Language: rules.LangCPP, Pattern: `\bconnect\s*\(\s*\w+\s*,`, ObjectType: "", MethodName: "connect", DangerousArgs: []int{1}, Severity: rules.High, Description: "Socket connect with user-controlled address", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "cpp.send.network", Category: taint.SnkURLFetch, Language: rules.LangCPP, Pattern: `\bsend\s*\(\s*\w+\s*,`, ObjectType: "", MethodName: "send", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "Socket send with tainted data", CWEID: "CWE-319", OWASPCategory: "A02:2021-Cryptographic Failures"},

		// ── HTML output / XSS (web frameworks) ────────────────────────
		{ID: "cpp.crow.response.write", Category: taint.SnkHTMLOutput, Language: rules.LangCPP, Pattern: `crow::response\s*\(|res\.write\s*\(`, ObjectType: "crow::response", MethodName: "response/write", DangerousArgs: []int{0}, Severity: rules.High, Description: "Crow HTTP response with tainted data (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "cpp.pistache.response.send", Category: taint.SnkHTMLOutput, Language: rules.LangCPP, Pattern: `response\.send\s*\(`, ObjectType: "Pistache::Http::ResponseWriter", MethodName: "send", DangerousArgs: []int{1}, Severity: rules.High, Description: "Pistache HTTP response with tainted data (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

		// ── Crypto sinks ──────────────────────────────────────────────
		{ID: "cpp.rand.insecure", Category: taint.SnkCrypto, Language: rules.LangCPP, Pattern: `\brand\s*\(\s*\)|\bsrand\s*\(`, ObjectType: "", MethodName: "rand/srand", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Insecure random number generator (use <random> engine)", CWEID: "CWE-338", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "cpp.openssl.des", Category: taint.SnkCrypto, Language: rules.LangCPP, Pattern: `DES_(?:ecb|cbc|cfb|ofb)_encrypt\s*\(`, ObjectType: "OpenSSL", MethodName: "DES_encrypt", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Weak DES encryption (use AES-256-GCM instead)", CWEID: "CWE-327", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "cpp.openssl.md5", Category: taint.SnkCrypto, Language: rules.LangCPP, Pattern: `\bMD5\s*\(|MD5_Init\s*\(`, ObjectType: "OpenSSL", MethodName: "MD5", DangerousArgs: []int{-1}, Severity: rules.Medium, Description: "Weak MD5 hash (use SHA-256 or better)", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "cpp.openssl.sha1", Category: taint.SnkCrypto, Language: rules.LangCPP, Pattern: `\bSHA1\s*\(|SHA1_Init\s*\(`, ObjectType: "OpenSSL", MethodName: "SHA1", DangerousArgs: []int{-1}, Severity: rules.Medium, Description: "Weak SHA-1 hash (use SHA-256 or better)", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},

		// ── XML parsing (XXE) ─────────────────────────────────────────
		{ID: "cpp.libxml2.parse", Category: taint.SnkXPath, Language: rules.LangCPP, Pattern: `xmlParseMemory\s*\(|xmlParseFile\s*\(|xmlCtxtReadMemory\s*\(`, ObjectType: "libxml2", MethodName: "xmlParse*", DangerousArgs: []int{0}, Severity: rules.High, Description: "XML parsing with potential XXE vulnerability", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},

		// ── Redirect ──────────────────────────────────────────────────
		{ID: "cpp.crow.redirect", Category: taint.SnkRedirect, Language: rules.LangCPP, Pattern: `crow::response\s*\(\s*30[12]|res\.redirect\s*\(`, ObjectType: "crow::response", MethodName: "redirect", DangerousArgs: []int{0}, Severity: rules.High, Description: "HTTP redirect with user-controlled URL", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},

		// ── LDAP injection ────────────────────────────────────────────
		{ID: "cpp.ldap.search", Category: taint.SnkLDAP, Language: rules.LangCPP, Pattern: `ldap_search(?:_ext)?(?:_s)?\s*\(`, ObjectType: "", MethodName: "ldap_search", DangerousArgs: []int{3}, Severity: rules.High, Description: "LDAP search with tainted filter", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "cpp.ldap.search.st", Category: taint.SnkLDAP, Language: rules.LangCPP, Pattern: `ldap_search_st\s*\(`, ObjectType: "", MethodName: "ldap_search_st", DangerousArgs: []int{3}, Severity: rules.High, Description: "OpenLDAP search with tainted filter and timeout", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},

		// ── HTTP header injection ─────────────────────────────────────
		{ID: "cpp.crow.header", Category: taint.SnkHeader, Language: rules.LangCPP, Pattern: `res\.set_header\s*\(|res\.add_header\s*\(`, ObjectType: "crow::response", MethodName: "set_header/add_header", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "Crow HTTP response header with tainted value", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
		{ID: "cpp.pistache.header", Category: taint.SnkHeader, Language: rules.LangCPP, Pattern: `response\.headers\s*\(\s*\)\s*\.add\s*\(|response\.headers\s*\(\s*\)\s*\.addRaw\s*\(`, ObjectType: "Pistache::Http::ResponseWriter", MethodName: "headers().add/addRaw", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "Pistache HTTP response header with tainted value", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
		{ID: "cpp.httplib.header", Category: taint.SnkHeader, Language: rules.LangCPP, Pattern: `res\.set_header\s*\(`, ObjectType: "httplib::Response", MethodName: "set_header", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "cpp-httplib response header with tainted value", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
		{ID: "cpp.drogon.header", Category: taint.SnkHeader, Language: rules.LangCPP, Pattern: `resp->addHeader\s*\(`, ObjectType: "drogon::HttpResponse", MethodName: "addHeader", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "Drogon response header with tainted value", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},

		// ── SSRF - Boost.Beast HTTP ───────────────────────────────────
		{ID: "cpp.boost.beast.http.write", Category: taint.SnkURLFetch, Language: rules.LangCPP, Pattern: `http::async_write\s*\(|http::write\s*\(`, ObjectType: "boost::beast::http", MethodName: "write/async_write", DangerousArgs: []int{1}, Severity: rules.High, Description: "Boost.Beast HTTP request write (SSRF if URL is tainted)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

		// ── Process creation (Windows) ────────────────────────────────
		{ID: "cpp.createprocess", Category: taint.SnkCommand, Language: rules.LangCPP, Pattern: `\bCreateProcess\w*\s*\(`, ObjectType: "", MethodName: "CreateProcess", DangerousArgs: []int{0, 1}, Severity: rules.Critical, Description: "Windows process creation with tainted arguments", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

		// ── Template injection ────────────────────────────────────────
		{ID: "cpp.inja.render", Category: taint.SnkTemplate, Language: rules.LangCPP, Pattern: `inja::render\s*\(|inja::Environment.*\.render\s*\(`, ObjectType: "inja", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.High, Description: "Inja template rendering with tainted data", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},

		// ── Dynamic library loading ───────────────────────────────────
		{ID: "cpp.dlopen", Category: taint.SnkEval, Language: rules.LangCPP, Pattern: `\bdlopen\s*\(`, ObjectType: "", MethodName: "dlopen", DangerousArgs: []int{0}, Severity: rules.High, Description: "Dynamic library loading with tainted path", CWEID: "CWE-829", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

		// --- Symlink attacks (CWE-59) ---
		{
			ID:            "cpp.file.symlink",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCPP,
			Pattern:       `\bsymlink\s*\(|std::filesystem::create_symlink\s*\(`,
			ObjectType:    "",
			MethodName:    "symlink/create_symlink",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Symlink creation with potentially tainted paths (symlink attack)",
			CWEID:         "CWE-59",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- std::filesystem operations ---
		{
			ID:            "cpp.filesystem.copy",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCPP,
			Pattern:       `std::filesystem::copy\s*\(|std::filesystem::copy_file\s*\(`,
			ObjectType:    "std::filesystem",
			MethodName:    "copy/copy_file",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Filesystem copy with potentially tainted paths",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "cpp.filesystem.rename",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCPP,
			Pattern:       `std::filesystem::rename\s*\(`,
			ObjectType:    "std::filesystem",
			MethodName:    "rename",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Filesystem rename with potentially tainted paths",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "cpp.filesystem.create_directories",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangCPP,
			Pattern:       `std::filesystem::create_director(?:y|ies)\s*\(`,
			ObjectType:    "std::filesystem",
			MethodName:    "create_directories",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Directory creation with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- ReDoS (CWE-1333) ---
		{
			ID:            "cpp.regex.construct",
			Category:      taint.SnkEval,
			Language:      rules.LangCPP,
			Pattern:       `std::regex\s*\(|std::regex\s+\w+\s*\(|boost::regex\s*\(`,
			ObjectType:    "std::regex",
			MethodName:    "regex constructor",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Regex construction with potentially tainted pattern (ReDoS risk)",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Format string (CWE-134) ---
		{
			ID:            "cpp.spdlog.format.tainted",
			Category:      taint.SnkLog,
			Language:      rules.LangCPP,
			Pattern:       `spdlog::(?:debug|trace|critical)\s*\(`,
			ObjectType:    "spdlog",
			MethodName:    "debug/trace/critical",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "spdlog logger with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},

		// --- Additional SSRF ---
		{
			ID:            "cpp.boost.beast.http.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangCPP,
			Pattern:       `boost::beast::http::request`,
			ObjectType:    "boost::beast::http",
			MethodName:    "request",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Boost.Beast HTTP request construction with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- Privilege (CWE-250) ---
		{
			ID:            "cpp.setuid",
			Category:      taint.SnkCommand,
			Language:      rules.LangCPP,
			Pattern:       `\bsetuid\s*\(|setgid\s*\(|seteuid\s*\(`,
			ObjectType:    "",
			MethodName:    "setuid/setgid",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Privilege change with potentially tainted value",
			CWEID:         "CWE-250",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Memory: use-after-free ---
		{
			ID:            "cpp.delete.dangling",
			Category:      taint.SnkCommand,
			Language:      rules.LangCPP,
			Pattern:       `\bdelete\s+`,
			ObjectType:    "",
			MethodName:    "delete",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Delete operation with potentially dangling or tainted pointer",
			CWEID:         "CWE-416",
			OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
		},

		// --- Poco HTTP redirect ---
		{
			ID:            "cpp.poco.redirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangCPP,
			Pattern:       `response\.redirect\s*\(|HTTPServerResponse.*redirect\s*\(`,
			ObjectType:    "Poco::Net::HTTPServerResponse",
			MethodName:    "redirect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "POCO HTTP redirect with potentially tainted URL",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
	}
}
