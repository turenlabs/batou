package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

func (phpCatalog) Sinks() []taint.SinkDef {
	return []taint.SinkDef{
		// SQL injection
		{ID: "php.mysql.query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\bmysql_query\s*\(`, ObjectType: "", MethodName: "mysql_query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via mysql_query", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.mysqli.query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\bmysqli_query\s*\(`, ObjectType: "", MethodName: "mysqli_query", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "SQL injection via mysqli_query", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.pdo.query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `->query\s*\(`, ObjectType: "PDO", MethodName: "query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via PDO::query", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// Command injection
		{ID: "php.exec", Category: taint.SnkCommand, Language: rules.LangPHP, Pattern: `\bexec\s*\(`, ObjectType: "", MethodName: "exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via exec()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.system", Category: taint.SnkCommand, Language: rules.LangPHP, Pattern: `\bsystem\s*\(`, ObjectType: "", MethodName: "system", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via system()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.passthru", Category: taint.SnkCommand, Language: rules.LangPHP, Pattern: `\bpassthru\s*\(`, ObjectType: "", MethodName: "passthru", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via passthru()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.shell_exec", Category: taint.SnkCommand, Language: rules.LangPHP, Pattern: `\bshell_exec\s*\(`, ObjectType: "", MethodName: "shell_exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via shell_exec()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.popen", Category: taint.SnkCommand, Language: rules.LangPHP, Pattern: `\bpopen\s*\(`, ObjectType: "", MethodName: "popen", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via popen()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.proc_open", Category: taint.SnkCommand, Language: rules.LangPHP, Pattern: `\bproc_open\s*\(`, ObjectType: "", MethodName: "proc_open", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via proc_open()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

		// Code evaluation
		{ID: "php.eval", Category: taint.SnkEval, Language: rules.LangPHP, Pattern: `\beval\s*\(`, ObjectType: "", MethodName: "eval", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Dynamic code evaluation via eval()", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.assert", Category: taint.SnkEval, Language: rules.LangPHP, Pattern: `\bassert\s*\(`, ObjectType: "", MethodName: "assert", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Dynamic code evaluation via assert()", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.preg_replace_e", Category: taint.SnkEval, Language: rules.LangPHP, Pattern: `\bpreg_replace\s*\(\s*['"]/[^/]*/e`, ObjectType: "", MethodName: "preg_replace", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "Code eval via preg_replace /e modifier", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

		// XSS
		{ID: "php.echo", Category: taint.SnkHTMLOutput, Language: rules.LangPHP, Pattern: `\becho\s+`, ObjectType: "", MethodName: "echo", DangerousArgs: []int{0}, Severity: rules.High, Description: "Unescaped output via echo", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.print", Category: taint.SnkHTMLOutput, Language: rules.LangPHP, Pattern: `\bprint\s+`, ObjectType: "", MethodName: "print", DangerousArgs: []int{0}, Severity: rules.High, Description: "Unescaped output via print", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.printf", Category: taint.SnkHTMLOutput, Language: rules.LangPHP, Pattern: `\bprintf\s*\(`, ObjectType: "", MethodName: "printf", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Unescaped output via printf", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

		// File inclusion (LFI/RFI)
		{ID: "php.include", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\binclude\s*\(`, ObjectType: "", MethodName: "include", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "File inclusion with user-controlled path", CWEID: "CWE-98", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.require", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\brequire\s*\(`, ObjectType: "", MethodName: "require", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "File inclusion via require()", CWEID: "CWE-98", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.include_once", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\binclude_once\s*\(`, ObjectType: "", MethodName: "include_once", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "File inclusion via include_once()", CWEID: "CWE-98", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.require_once", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\brequire_once\s*\(`, ObjectType: "", MethodName: "require_once", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "File inclusion via require_once()", CWEID: "CWE-98", OWASPCategory: "A03:2021-Injection"},

		// File operations
		{ID: "php.file_put_contents", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\bfile_put_contents\s*\(`, ObjectType: "", MethodName: "file_put_contents", DangerousArgs: []int{0}, Severity: rules.High, Description: "File write with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.fwrite", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\bfwrite\s*\(`, ObjectType: "", MethodName: "fwrite", DangerousArgs: []int{1}, Severity: rules.High, Description: "File write via fwrite()", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.fopen", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\bfopen\s*\(`, ObjectType: "", MethodName: "fopen", DangerousArgs: []int{0}, Severity: rules.High, Description: "File open with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// Header injection
		{ID: "php.header", Category: taint.SnkHeader, Language: rules.LangPHP, Pattern: `\bheader\s*\(`, ObjectType: "", MethodName: "header", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "HTTP header injection", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.setcookie", Category: taint.SnkHeader, Language: rules.LangPHP, Pattern: `\bsetcookie\s*\(`, ObjectType: "", MethodName: "setcookie", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "Cookie injection via setcookie()", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},

		// Deserialization
		{ID: "php.unserialize", Category: taint.SnkDeserialize, Language: rules.LangPHP, Pattern: `\bunserialize\s*\(`, ObjectType: "", MethodName: "unserialize", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Unsafe PHP deserialization", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

		// Redirect
		{ID: "php.redirect", Category: taint.SnkRedirect, Language: rules.LangPHP, Pattern: `\bredirect\s*\(`, ObjectType: "", MethodName: "redirect", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via redirect()", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.header.location", Category: taint.SnkRedirect, Language: rules.LangPHP, Pattern: `header\s*\(\s*["']Location\s*:`, ObjectType: "", MethodName: "header(Location)", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via Location header", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},

		// SSRF
		{ID: "php.file_get_contents.ssrf", Category: taint.SnkURLFetch, Language: rules.LangPHP, Pattern: `\bfile_get_contents\s*\(`, ObjectType: "", MethodName: "file_get_contents", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via file_get_contents()", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "php.curl_exec", Category: taint.SnkURLFetch, Language: rules.LangPHP, Pattern: `\bcurl_exec\s*\(`, ObjectType: "", MethodName: "curl_exec", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via curl_exec()", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

		// LDAP
		{ID: "php.ldap_search", Category: taint.SnkLDAP, Language: rules.LangPHP, Pattern: `\bldap_search\s*\(`, ObjectType: "", MethodName: "ldap_search", DangerousArgs: []int{2}, Severity: rules.High, Description: "LDAP injection via ldap_search()", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},

		// Laravel framework sinks
		{ID: "php.laravel.db.raw", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `DB::raw\s*\(`, ObjectType: "DB", MethodName: "DB::raw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via Laravel DB::raw()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.laravel.whereRaw", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `->whereRaw\s*\(`, ObjectType: "Eloquent", MethodName: "whereRaw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via Eloquent whereRaw()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.laravel.selectRaw", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `->selectRaw\s*\(`, ObjectType: "Eloquent", MethodName: "selectRaw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via Eloquent selectRaw()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.laravel.orderByRaw", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `->orderByRaw\s*\(`, ObjectType: "Eloquent", MethodName: "orderByRaw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via Eloquent orderByRaw()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.laravel.blade.unescaped", Category: taint.SnkHTMLOutput, Language: rules.LangPHP, Pattern: `\{!!\s*.*\s*!!\}`, ObjectType: "", MethodName: "{!! !!}", DangerousArgs: []int{0}, Severity: rules.High, Description: "XSS via Blade unescaped output {!! !!}", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

		// Symfony / Twig template sinks
		{ID: "php.twig.raw.filter", Category: taint.SnkHTMLOutput, Language: rules.LangPHP, Pattern: `\|\s*raw\b`, ObjectType: "", MethodName: "|raw", DangerousArgs: []int{0}, Severity: rules.High, Description: "XSS via Twig |raw filter (disables escaping)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.twig.autoescape.false", Category: taint.SnkHTMLOutput, Language: rules.LangPHP, Pattern: `autoescape\s+false`, ObjectType: "", MethodName: "autoescape false", DangerousArgs: []int{-1}, Severity: rules.High, Description: "XSS via Twig autoescape disabled", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

		// CodeIgniter framework sinks
		{ID: "php.codeigniter.db.query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\$this->db->query\s*\(`, ObjectType: "CI_DB", MethodName: "query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via CodeIgniter db->query()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// WordPress sinks
		{ID: "php.wordpress.wpdb.query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\$wpdb->query\s*\(`, ObjectType: "wpdb", MethodName: "query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via WordPress wpdb->query()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.wordpress.wpdb.get_results", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\$wpdb->get_results\s*\(`, ObjectType: "wpdb", MethodName: "get_results", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via WordPress wpdb->get_results()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.wordpress.update_option", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\bupdate_option\s*\(`, ObjectType: "", MethodName: "update_option", DangerousArgs: []int{1}, Severity: rules.High, Description: "Arbitrary option update via update_option()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// Mail header injection
		{ID: "php.mail", Category: taint.SnkHeader, Language: rules.LangPHP, Pattern: `\bmail\s*\(`, ObjectType: "", MethodName: "mail", DangerousArgs: []int{0, 1, 3}, Severity: rules.High, Description: "Email header injection via mail()", CWEID: "CWE-93", OWASPCategory: "A03:2021-Injection"},

		// Variable injection
		{ID: "php.extract", Category: taint.SnkEval, Language: rules.LangPHP, Pattern: `\bextract\s*\(`, ObjectType: "", MethodName: "extract", DangerousArgs: []int{0}, Severity: rules.High, Description: "Variable injection via extract() overwrites local scope", CWEID: "CWE-621", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.parse_str", Category: taint.SnkEval, Language: rules.LangPHP, Pattern: `\bparse_str\s*\(`, ObjectType: "", MethodName: "parse_str", DangerousArgs: []int{0}, Severity: rules.High, Description: "Variable overwrite via parse_str() without second argument", CWEID: "CWE-621", OWASPCategory: "A03:2021-Injection"},

		// XXE (XML External Entity)
		{ID: "php.simplexml_load_string", Category: taint.SnkDeserialize, Language: rules.LangPHP, Pattern: `\bsimplexml_load_string\s*\(`, ObjectType: "", MethodName: "simplexml_load_string", DangerousArgs: []int{0}, Severity: rules.High, Description: "XXE via simplexml_load_string() with external entities", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
		{ID: "php.dom.loadxml", Category: taint.SnkDeserialize, Language: rules.LangPHP, Pattern: `->loadXML\s*\(`, ObjectType: "DOMDocument", MethodName: "loadXML", DangerousArgs: []int{0}, Severity: rules.High, Description: "XXE via DOMDocument::loadXML() with external entities", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
		{ID: "php.simplexml_load_file", Category: taint.SnkDeserialize, Language: rules.LangPHP, Pattern: `\bsimplexml_load_file\s*\(`, ObjectType: "", MethodName: "simplexml_load_file", DangerousArgs: []int{0}, Severity: rules.High, Description: "XXE via simplexml_load_file() with external entities", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},

		// File upload to tainted path
		{ID: "php.move_uploaded_file", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\bmove_uploaded_file\s*\(`, ObjectType: "", MethodName: "move_uploaded_file", DangerousArgs: []int{1}, Severity: rules.High, Description: "File upload to user-controlled path via move_uploaded_file()", CWEID: "CWE-434", OWASPCategory: "A01:2021-Broken Access Control"},

		// Weak cryptographic hash (CWE-328)
		{ID: "php.crypto.md5", Category: taint.SnkCrypto, Language: rules.LangPHP, Pattern: `\bmd5\s*\(`, ObjectType: "", MethodName: "md5", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Weak MD5 hash usage (use password_hash or hash('sha256') instead)", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "php.crypto.sha1", Category: taint.SnkCrypto, Language: rules.LangPHP, Pattern: `\bsha1\s*\(`, ObjectType: "", MethodName: "sha1", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Weak SHA1 hash usage", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},

		// Insecure random (CWE-338)
		{ID: "php.crypto.rand", Category: taint.SnkCrypto, Language: rules.LangPHP, Pattern: `\brand\s*\(|\bmt_rand\s*\(`, ObjectType: "", MethodName: "rand/mt_rand", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Non-cryptographic random used for security (use random_bytes/random_int instead)", CWEID: "CWE-338", OWASPCategory: "A02:2021-Cryptographic Failures"},

		// Weak encryption (CWE-327)
		{ID: "php.crypto.mcrypt", Category: taint.SnkCrypto, Language: rules.LangPHP, Pattern: `\bmcrypt_encrypt\s*\(|\bmcrypt_decrypt\s*\(`, ObjectType: "", MethodName: "mcrypt_*", DangerousArgs: []int{0}, Severity: rules.High, Description: "Deprecated mcrypt library usage (use openssl_encrypt instead)", CWEID: "CWE-327", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "php.crypto.ecb_mode", Category: taint.SnkCrypto, Language: rules.LangPHP, Pattern: `MCRYPT_MODE_ECB|openssl_encrypt\s*\(.*ecb`, ObjectType: "", MethodName: "ECB mode", DangerousArgs: []int{-1}, Severity: rules.High, Description: "ECB mode cipher usage (no diffusion, use CBC/GCM)", CWEID: "CWE-327", OWASPCategory: "A02:2021-Cryptographic Failures"},

		// Redis command injection (Predis/phpredis)
		{ID: "php.redis.eval", Category: taint.SnkEval, Language: rules.LangPHP, Pattern: `->eval\s*\(`, ObjectType: "Redis", MethodName: "eval", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Redis Lua script evaluation with tainted script", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.redis.rawcommand", Category: taint.SnkCommand, Language: rules.LangPHP, Pattern: `->rawCommand\s*\(`, ObjectType: "Redis", MethodName: "rawCommand", DangerousArgs: []int{0}, Severity: rules.High, Description: "Redis raw command execution with tainted arguments", CWEID: "CWE-77", OWASPCategory: "A03:2021-Injection"},

		// DNS lookup with tainted hostname
		{ID: "php.dns_get_record", Category: taint.SnkURLFetch, Language: rules.LangPHP, Pattern: `\bdns_get_record\s*\(|\bgethostbyname\s*\(`, ObjectType: "", MethodName: "dns_get_record/gethostbyname", DangerousArgs: []int{0}, Severity: rules.High, Description: "DNS lookup with tainted hostname (SSRF/DNS rebinding)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

		// SMTP header injection (PHPMailer/SwiftMailer)
		{ID: "php.phpmailer.addaddress", Category: taint.SnkHeader, Language: rules.LangPHP, Pattern: `->addAddress\s*\(|->addCC\s*\(|->addBCC\s*\(`, ObjectType: "PHPMailer", MethodName: "addAddress", DangerousArgs: []int{0}, Severity: rules.High, Description: "PHPMailer address/header injection with tainted recipient", CWEID: "CWE-93", OWASPCategory: "A03:2021-Injection"},

		// Docker exec
		{ID: "php.docker.exec", Category: taint.SnkCommand, Language: rules.LangPHP, Pattern: `->exec\s*\(|->containerExec\s*\(`, ObjectType: "Docker\\API", MethodName: "exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Docker container exec with tainted command", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

		// AMQP message construction
		{ID: "php.amqp.publish", Category: taint.SnkCommand, Language: rules.LangPHP, Pattern: `->basic_publish\s*\(|->publish\s*\(`, ObjectType: "AMQPChannel", MethodName: "basic_publish", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "AMQP message published with tainted data", CWEID: "CWE-77", OWASPCategory: "A03:2021-Injection"},

		// Log injection (CWE-117)
		{ID: "php.error_log", Category: taint.SnkLog, Language: rules.LangPHP, Pattern: `\berror_log\s*\(`, ObjectType: "", MethodName: "error_log", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "error_log with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "php.syslog", Category: taint.SnkLog, Language: rules.LangPHP, Pattern: `\bsyslog\s*\(`, ObjectType: "", MethodName: "syslog", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "syslog with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "php.laravel.log.info", Category: taint.SnkLog, Language: rules.LangPHP, Pattern: `Log::(?:info|warning|error|debug|critical|emergency|notice|alert)\s*\(`, ObjectType: "Log", MethodName: "Log::*", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Laravel Log facade with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "php.monolog.log", Category: taint.SnkLog, Language: rules.LangPHP, Pattern: `->(?:info|warning|error|debug|critical|emergency|notice|alert)\s*\(`, ObjectType: "Monolog\\Logger", MethodName: "Logger->*", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Monolog logger with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},

		// --- File operations (CWE-22) ---
		{
			ID:            "php.symlink",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPHP,
			Pattern:       `\bsymlink\s*\(`,
			ObjectType:    "",
			MethodName:    "symlink",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Symlink creation with potentially tainted paths (symlink attack)",
			CWEID:         "CWE-59",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "php.link",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPHP,
			Pattern:       `\blink\s*\(`,
			ObjectType:    "",
			MethodName:    "link",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Hard link creation with potentially tainted paths",
			CWEID:         "CWE-59",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "php.mkdir",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPHP,
			Pattern:       `\bmkdir\s*\(`,
			ObjectType:    "",
			MethodName:    "mkdir",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Directory creation with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "php.rename",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPHP,
			Pattern:       `\brename\s*\(`,
			ObjectType:    "",
			MethodName:    "rename",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "File rename with potentially tainted paths",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "php.copy",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPHP,
			Pattern:       `\bcopy\s*\(`,
			ObjectType:    "",
			MethodName:    "copy",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "File copy with potentially tainted paths",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- ReDoS (CWE-1333) ---
		{
			ID:            "php.preg_match.tainted",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `preg_match\s*\(|preg_match_all\s*\(`,
			ObjectType:    "",
			MethodName:    "preg_match",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Regex match with potentially tainted pattern (ReDoS risk)",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Dynamic Code (CWE-94) ---
		{
			ID:            "php.create_function",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `create_function\s*\(`,
			ObjectType:    "",
			MethodName:    "create_function",
			DangerousArgs: []int{0, 1},
			Severity:      rules.Critical,
			Description:   "Deprecated create_function with potentially tainted body (code injection)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.call_user_func",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `call_user_func\s*\(|call_user_func_array\s*\(`,
			ObjectType:    "",
			MethodName:    "call_user_func",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Dynamic function call with potentially tainted function name",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Variable injection (CWE-621) ---
		{
			ID:            "php.compact",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `\bcompact\s*\(`,
			ObjectType:    "",
			MethodName:    "compact",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Variable extraction via compact with potentially tainted variable names",
			CWEID:         "CWE-621",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Cookie injection (CWE-113) ---
		{
			ID:            "php.setrawcookie",
			Category:      taint.SnkHeader,
			Language:      rules.LangPHP,
			Pattern:       `\bsetrawcookie\s*\(`,
			ObjectType:    "",
			MethodName:    "setrawcookie",
			DangerousArgs: []int{0, 1},
			Severity:      rules.Medium,
			Description:   "Raw cookie set without URL encoding with potentially tainted value",
			CWEID:         "CWE-113",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Additional deserialization (CWE-502) ---
		{
			ID:            "php.json_decode",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPHP,
			Pattern:       `json_decode\s*\(`,
			ObjectType:    "",
			MethodName:    "json_decode",
			DangerousArgs: []int{0},
			Severity:      rules.Low,
			Description:   "JSON decode of potentially tainted data",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- SSRF additional (CWE-918) ---
		{
			ID:            "php.guzzle.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPHP,
			Pattern:       `\$client->request\s*\(|\$client->get\s*\(|\$client->post\s*\(`,
			ObjectType:    "GuzzleHttp\\Client",
			MethodName:    "request/get/post",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "Guzzle HTTP request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- Laravel DB::select (CWE-89) ---
		{
			ID:            "php.laravel.db.select",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `DB::select\s*\(`,
			ObjectType:    "DB",
			MethodName:    "DB::select",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL injection via Laravel DB::select() with concatenated query",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- PDO exec (CWE-89) ---
		{
			ID:            "php.pdo.exec",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->exec\s*\(`,
			ObjectType:    "PDO",
			MethodName:    "exec",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL injection via PDO::exec() with tainted SQL",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- File deletion (CWE-22) ---
		{
			ID:            "php.unlink",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPHP,
			Pattern:       `\bunlink\s*\(`,
			ObjectType:    "",
			MethodName:    "unlink",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File deletion with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- SoapClient SSRF (CWE-918) ---
		{
			ID:            "php.soapclient",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPHP,
			Pattern:       `new\s+SoapClient\s*\(`,
			ObjectType:    "SoapClient",
			MethodName:    "SoapClient",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via SoapClient with tainted WSDL URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- session_set_cookie_params (CWE-384) ---
		{
			ID:            "php.session.cookie_params",
			Category:      taint.SnkHeader,
			Language:      rules.LangPHP,
			Pattern:       `\bsession_set_cookie_params\s*\(`,
			ObjectType:    "",
			MethodName:    "session_set_cookie_params",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Session cookie parameters set with potentially tainted values",
			CWEID:         "CWE-384",
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
		},

		// --- Template Injection (CWE-1336) ---
		{
			ID:            "php.smarty.display",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPHP,
			Pattern:       `->display\s*\(`,
			ObjectType:    "Smarty",
			MethodName:    "display",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Smarty template rendering with potentially tainted template name",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.smarty.fetch",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPHP,
			Pattern:       `->fetch\s*\(`,
			ObjectType:    "Smarty",
			MethodName:    "fetch",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Smarty template fetch with potentially tainted template name",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.twig.render",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPHP,
			Pattern:       `->render\s*\(`,
			ObjectType:    "Twig\\Environment",
			MethodName:    "render",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Twig template rendering with potentially tainted template name",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.blade.render",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPHP,
			Pattern:       `Blade::render\s*\(|view\s*\(`,
			ObjectType:    "Blade",
			MethodName:    "Blade::render/view",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Laravel Blade template rendering with potentially tainted template name",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- XPath Injection (CWE-643) ---
		{
			ID:            "php.domxpath.query",
			Category:      taint.SnkXPath,
			Language:      rules.LangPHP,
			Pattern:       `DOMXPath.*->query\s*\(`,
			ObjectType:    "DOMXPath",
			MethodName:    "query",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XPath query with potentially tainted expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.domxpath.evaluate",
			Category:      taint.SnkXPath,
			Language:      rules.LangPHP,
			Pattern:       `DOMXPath.*->evaluate\s*\(`,
			ObjectType:    "DOMXPath",
			MethodName:    "evaluate",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XPath evaluation with potentially tainted expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.simplexml.xpath",
			Category:      taint.SnkXPath,
			Language:      rules.LangPHP,
			Pattern:       `->xpath\s*\(`,
			ObjectType:    "SimpleXMLElement",
			MethodName:    "xpath",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SimpleXML XPath query with potentially tainted expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
	}
}
