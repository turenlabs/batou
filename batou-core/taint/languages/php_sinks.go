package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (phpCatalog) Sinks() []taint.SinkDef {
	return []taint.SinkDef{
		// SQL injection
		{ID: "php.mysql.query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\bmysql_query\s*\(`, ObjectType: "", MethodName: "mysql_query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via mysql_query", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.mysqli.query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\bmysqli_query\s*\(`, ObjectType: "", MethodName: "mysqli_query", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "SQL injection via mysqli_query", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		// mysqli_multi_query / mysqli_real_query — procedural forms; complement
		// php.mysqli.query (single-statement). multi_query is particularly
		// dangerous because it permits stacked statements (classic
		// stacked-queries attack: "id=1; DROP TABLE users;").
		{ID: "php.mysqli.multi_query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\bmysqli_multi_query\s*\(`, ObjectType: "", MethodName: "mysqli_multi_query", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "SQL injection via mysqli_multi_query — allows stacked queries (multiple statements separated by ';')", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.mysqli.real_query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\bmysqli_real_query\s*\(`, ObjectType: "", MethodName: "mysqli_real_query", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "SQL injection via mysqli_real_query (executes query without buffering results)", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		// mysqli OO forms — $mysqli->query() / multi_query() / real_query();
		// PHP's object-oriented mysqli API, used by most modern PHP code and
		// by frameworks like CodeIgniter 3. The procedural entry above does
		// not match these because the method name differs ("query" vs
		// "mysqli_query").
		{ID: "php.mysqli.oo.query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `->query\s*\(`, ObjectType: "mysqli", MethodName: "query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via mysqli::query (OO form: $mysqli->query($sql))", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.mysqli.oo.multi_query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `->multi_query\s*\(`, ObjectType: "mysqli", MethodName: "multi_query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via mysqli::multi_query (OO form) — allows stacked queries", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.mysqli.oo.real_query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `->real_query\s*\(`, ObjectType: "mysqli", MethodName: "real_query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via mysqli::real_query (OO form)", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
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

		// Archive extraction sinks (Zip Slip / Tar Slip, CWE-22). Extracting an
		// archive into a user-controlled destination directory writes files to
		// an attacker-chosen location (path traversal / arbitrary write); the
		// same flaw class as ruby.rubyzip.entry.extract, py.archive.extractall
		// and js.admzip.extractAllTo. PHP's ZipArchive::extractTo() and the
		// Phar/PharData::extractTo() family take the destination directory as
		// the first argument. Fix by validating the destination with realpath()
		// and confirming it stays inside the intended base directory.
		{ID: "php.ziparchive.extractto", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `->extractTo\s*\(`, ObjectType: "ZipArchive", MethodName: "extractTo", DangerousArgs: []int{0}, Severity: rules.High, Description: "ZipArchive::extractTo() with tainted destination directory — archive contents are written to an attacker-chosen path (Zip Slip / path traversal)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.phardata.extractto", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `->extractTo\s*\(`, ObjectType: "PharData", MethodName: "extractTo", DangerousArgs: []int{0}, Severity: rules.High, Description: "PharData::extractTo() with tainted destination directory — tar/zip contents are written to an attacker-chosen path (Tar Slip / path traversal)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.phar.extractto", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `->extractTo\s*\(`, ObjectType: "Phar", MethodName: "extractTo", DangerousArgs: []int{0}, Severity: rules.High, Description: "Phar::extractTo() with tainted destination directory — archive contents are written to an attacker-chosen path (path traversal)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// CSV / spreadsheet formula injection (CWE-1236) — fputcsv($handle,
		// $fields) writes a CSV record; when $fields holds user-controlled
		// values, cells beginning with =, +, -, @, tab or CR are interpreted
		// as formulas by Excel / LibreOffice / Google Sheets when the file
		// is opened (DDE / command execution on the viewer's machine). The
		// dangerous arg is the $fields array (arg index 1).
		{ID: "php.fputcsv", Category: taint.SnkCSV, Language: rules.LangPHP, Pattern: `\bfputcsv\s*\(`, ObjectType: "", MethodName: "fputcsv", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "fputcsv() with user-controlled $fields — values beginning with =, +, -, @ become formulas when the CSV is opened in a spreadsheet (CSV/formula injection)", CWEID: "CWE-1236", OWASPCategory: "A03:2021-Injection"},

		// Header injection
		//
		// The two open-redirect (CWE-601) specialisations of header() — Location and
		// Refresh — are listed FIRST so that for a `header("Location: " . $url)` call
		// the matcher returns the more-specific open-redirect classification rather
		// than the generic CWE-113 header-injection one. Both are wildcard-ObjectType
		// and the tsflow matcher returns the first catalog-order entry whose Pattern
		// re-validates against the call text, so ordering is the selector. A plain
		// header() with no Location/Refresh value falls through to php.header below.
		// (See the detailed note in the Redirect section for why MethodName is the
		// bare "header" and why the header name is matched case-insensitively.)
		{ID: "php.header.location", Category: taint.SnkRedirect, Language: rules.LangPHP, Pattern: `\bheader\s*\(\s*["'](?i:location)\s*:`, ObjectType: "", MethodName: "header", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via Location header", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.header.refresh", Category: taint.SnkRedirect, Language: rules.LangPHP, Pattern: `\bheader\s*\(\s*["'](?i:refresh)\s*:`, ObjectType: "", MethodName: "header", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via HTTP Refresh header with tainted URL", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.header", Category: taint.SnkHeader, Language: rules.LangPHP, Pattern: `\bheader\s*\(`, ObjectType: "", MethodName: "header", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "HTTP header injection", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.setcookie", Category: taint.SnkHeader, Language: rules.LangPHP, Pattern: `\bsetcookie\s*\(`, ObjectType: "", MethodName: "setcookie", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "Cookie injection via setcookie()", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},

		// Deserialization
		{ID: "php.unserialize", Category: taint.SnkDeserialize, Language: rules.LangPHP, Pattern: `\bunserialize\s*\(`, ObjectType: "", MethodName: "unserialize", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Unsafe PHP deserialization", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

		// WordPress maybe_unserialize — thin wrapper around unserialize() that runs whenever the input is a serialized string (CWE-502)
		{ID: "php.wordpress.maybe_unserialize", Category: taint.SnkDeserialize, Language: rules.LangPHP, Pattern: `\bmaybe_unserialize\s*\(`, ObjectType: "@global", MethodName: "maybe_unserialize", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "WordPress maybe_unserialize() — PHP object injection via gadget chain when input is untrusted", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

		// Laravel Encrypter — Crypt::decrypt() unserializes by default; RCE via gadget chain if APP_KEY leaks (CVE-2018-15133)
		{ID: "php.laravel.crypt.decrypt", Category: taint.SnkDeserialize, Language: rules.LangPHP, Pattern: `Crypt::decrypt\s*\(`, ObjectType: "Crypt", MethodName: "decrypt", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Laravel Crypt::decrypt() unserializes by default — RCE via gadget chain if APP_KEY is leaked (CVE-2018-15133)", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

		// Symfony Serializer / JMS Serializer — ->deserialize() instantiates user-specified class with magic methods (CWE-502)
		{ID: "php.serializer.deserialize", Category: taint.SnkDeserialize, Language: rules.LangPHP, Pattern: `->\s*deserialize\s*\(`, ObjectType: "Serializer", MethodName: "deserialize", DangerousArgs: []int{0}, Severity: rules.High, Description: "Symfony/JMS Serializer::deserialize() — PHP object injection via magic methods on tainted input", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

		// PHP yaml_parse — YAML !php/object tag instantiates arbitrary classes on deserialization (CWE-502)
		{ID: "php.yaml_parse", Category: taint.SnkDeserialize, Language: rules.LangPHP, Pattern: `\byaml_parse\s*\(`, ObjectType: "@global", MethodName: "yaml_parse", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "PHP yaml_parse() — !php/object tag instantiates arbitrary classes on untrusted YAML input", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
		// Symfony Yaml component — Yaml::parse() / Yaml::parseFile() (and the OO
		// Parser->parse()) deserialize untrusted YAML. With the PARSE_OBJECT or
		// PARSE_OBJECT_FOR_MAP flag (or the legacy `true` 2nd arg in older
		// versions) the `!php/object` tag instantiates and unserializes an
		// arbitrary class → PHP object injection / RCE via a gadget chain. This is
		// the dominant YAML entry point in Symfony apps and is distinct from the
		// ext-yaml `yaml_parse()` global covered above. Anchored on the
		// Yaml::parse static call and the Symfony Yaml `Parser` ObjectType so a
		// bare `->parse()` on an unrelated object does not match.
		{ID: "php.symfony.yaml.parse", Category: taint.SnkDeserialize, Language: rules.LangPHP, Pattern: `\bYaml::parse(?:File)?\s*\(`, ObjectType: "Yaml", MethodName: "parse/parseFile", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Symfony Yaml::parse()/parseFile() on untrusted YAML — the !php/object tag (PARSE_OBJECT flag) instantiates and unserializes arbitrary classes, enabling PHP object injection / RCE via a gadget chain (CWE-502). Parse untrusted YAML without PARSE_OBJECT and never from user input.", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
		{ID: "php.symfony.yaml.parser", Category: taint.SnkDeserialize, Language: rules.LangPHP, Pattern: `(?:Parser|\$yamlParser|\$parser)\s*->\s*parse\s*\(`, ObjectType: "Symfony\\Component\\Yaml\\Parser", MethodName: "parse", DangerousArgs: []int{0}, Severity: rules.High, Description: "Symfony Yaml Parser::parse() on untrusted YAML — !php/object instantiates arbitrary classes when PARSE_OBJECT is set (CWE-502 PHP object injection).", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

		// Redirect
		{ID: "php.redirect", Category: taint.SnkRedirect, Language: rules.LangPHP, Pattern: `\bredirect\s*\(`, ObjectType: "", MethodName: "redirect", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via redirect()", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},
		// NOTE: the header("Location:")/header("Refresh:") open-redirect sinks
		// (php.header.location / php.header.refresh, CWE-601) live in the Header
		// injection section above so they precede the generic CWE-113 php.header
		// entry — ordering selects the more-specific classification. See that note.
		{ID: "php.wp.redirect", Category: taint.SnkRedirect, Language: rules.LangPHP, Pattern: `\bwp_redirect\s*\(`, ObjectType: "", MethodName: "wp_redirect", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via WordPress wp_redirect() (CVE-2024-4704)", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.wp.safe_redirect", Category: taint.SnkRedirect, Language: rules.LangPHP, Pattern: `\bwp_safe_redirect\s*\(`, ObjectType: "", MethodName: "wp_safe_redirect", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "WordPress wp_safe_redirect() with tainted URL (validates against allowed hosts)", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.http_redirect", Category: taint.SnkRedirect, Language: rules.LangPHP, Pattern: `\bhttp_redirect\s*\(`, ObjectType: "", MethodName: "http_redirect", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via PECL http_redirect() with tainted URL", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.psr7.withredirect", Category: taint.SnkRedirect, Language: rules.LangPHP, Pattern: `->withRedirect\s*\(`, ObjectType: "ResponseInterface", MethodName: "withRedirect", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via PSR-7/Slim withRedirect() with tainted URL", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.laravel.redirect.facade", Category: taint.SnkRedirect, Language: rules.LangPHP, Pattern: `Redirect::to\s*\(`, ObjectType: "Redirect", MethodName: "Redirect::to", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via Laravel Redirect::to() facade with tainted URL", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},

		// SSRF
		{ID: "php.file_get_contents.ssrf", Category: taint.SnkURLFetch, Language: rules.LangPHP, Pattern: `\bfile_get_contents\s*\(`, ObjectType: "", MethodName: "file_get_contents", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via file_get_contents()", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "php.curl_exec", Category: taint.SnkURLFetch, Language: rules.LangPHP, Pattern: `\bcurl_exec\s*\(`, ObjectType: "", MethodName: "curl_exec", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via curl_exec()", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

		// WordPress HTTP API — SSRF when the URL argument is user-controlled.
		// The wp_remote_*() family does NOT validate the target host against
		// internal/loopback ranges; wp_safe_remote_*() (registered as
		// sanitizers) does. Real-world exploits: CVE-2024-1071 (Ultimate
		// Member), CVE-2023-48329 (Paid Memberships Pro), and many other
		// plugin SSRFs. download_url() likewise fetches a URL into a temp
		// file and is exploitable when the URL is tainted.
		{ID: "php.wordpress.wp_remote_get.ssrf", Category: taint.SnkURLFetch, Language: rules.LangPHP, Pattern: `\bwp_remote_get\s*\(`, ObjectType: "", MethodName: "wp_remote_get", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via WordPress wp_remote_get() with tainted URL (use wp_safe_remote_get instead)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "php.wordpress.wp_remote_post.ssrf", Category: taint.SnkURLFetch, Language: rules.LangPHP, Pattern: `\bwp_remote_post\s*\(`, ObjectType: "", MethodName: "wp_remote_post", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via WordPress wp_remote_post() with tainted URL (use wp_safe_remote_post instead)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "php.wordpress.wp_remote_request.ssrf", Category: taint.SnkURLFetch, Language: rules.LangPHP, Pattern: `\bwp_remote_request\s*\(`, ObjectType: "", MethodName: "wp_remote_request", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via WordPress wp_remote_request() with tainted URL (use wp_safe_remote_request instead)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "php.wordpress.wp_remote_head.ssrf", Category: taint.SnkURLFetch, Language: rules.LangPHP, Pattern: `\bwp_remote_head\s*\(`, ObjectType: "", MethodName: "wp_remote_head", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via WordPress wp_remote_head() with tainted URL (use wp_safe_remote_head instead)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "php.wordpress.download_url.ssrf", Category: taint.SnkURLFetch, Language: rules.LangPHP, Pattern: `\bdownload_url\s*\(`, ObjectType: "", MethodName: "download_url", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via WordPress download_url() with tainted URL — fetches the target into a temp file", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

		// LDAP — filter injection (filter param at arg 2)
		{ID: "php.ldap_search", Category: taint.SnkLDAP, Language: rules.LangPHP, Pattern: `\bldap_search\s*\(`, ObjectType: "", MethodName: "ldap_search", DangerousArgs: []int{2}, Severity: rules.High, Description: "LDAP injection via ldap_search()", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.ldap_list", Category: taint.SnkLDAP, Language: rules.LangPHP, Pattern: `\bldap_list\s*\(`, ObjectType: "", MethodName: "ldap_list", DangerousArgs: []int{2}, Severity: rules.High, Description: "LDAP injection via ldap_list() single-level search", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.ldap_read", Category: taint.SnkLDAP, Language: rules.LangPHP, Pattern: `\bldap_read\s*\(`, ObjectType: "", MethodName: "ldap_read", DangerousArgs: []int{2}, Severity: rules.High, Description: "LDAP injection via ldap_read() entry read", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},

		// LDAP — DN injection (DN param at arg 1)
		{ID: "php.ldap_bind", Category: taint.SnkLDAP, Language: rules.LangPHP, Pattern: `\bldap_bind(?:_ext)?\s*\(`, ObjectType: "", MethodName: "ldap_bind", DangerousArgs: []int{1}, Severity: rules.High, Description: "LDAP DN injection via ldap_bind() authentication", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.ldap_sasl_bind", Category: taint.SnkLDAP, Language: rules.LangPHP, Pattern: `\bldap_sasl_bind\s*\(`, ObjectType: "", MethodName: "ldap_sasl_bind", DangerousArgs: []int{1}, Severity: rules.High, Description: "LDAP DN injection via ldap_sasl_bind() SASL authentication", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.ldap_compare", Category: taint.SnkLDAP, Language: rules.LangPHP, Pattern: `\bldap_compare\s*\(`, ObjectType: "", MethodName: "ldap_compare", DangerousArgs: []int{1}, Severity: rules.High, Description: "LDAP DN injection via ldap_compare() attribute comparison", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.ldap_add", Category: taint.SnkLDAP, Language: rules.LangPHP, Pattern: `\bldap_add(?:_ext)?\s*\(`, ObjectType: "", MethodName: "ldap_add", DangerousArgs: []int{1}, Severity: rules.High, Description: "LDAP DN injection via ldap_add() entry creation", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.ldap_delete", Category: taint.SnkLDAP, Language: rules.LangPHP, Pattern: `\bldap_delete(?:_ext)?\s*\(`, ObjectType: "", MethodName: "ldap_delete", DangerousArgs: []int{1}, Severity: rules.High, Description: "LDAP DN injection via ldap_delete() entry deletion", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.ldap_modify", Category: taint.SnkLDAP, Language: rules.LangPHP, Pattern: `\b(?:ldap_modify|ldap_mod_replace)(?:_ext)?\s*\(`, ObjectType: "", MethodName: "ldap_modify", DangerousArgs: []int{1}, Severity: rules.High, Description: "LDAP DN injection via ldap_modify()/ldap_mod_replace() attribute replacement", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.ldap_modify_batch", Category: taint.SnkLDAP, Language: rules.LangPHP, Pattern: `\bldap_modify_batch\s*\(`, ObjectType: "", MethodName: "ldap_modify_batch", DangerousArgs: []int{1}, Severity: rules.High, Description: "LDAP DN injection via ldap_modify_batch() batch modification", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.ldap_mod_add", Category: taint.SnkLDAP, Language: rules.LangPHP, Pattern: `\bldap_mod_add(?:_ext)?\s*\(`, ObjectType: "", MethodName: "ldap_mod_add", DangerousArgs: []int{1}, Severity: rules.High, Description: "LDAP DN injection via ldap_mod_add() attribute addition", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.ldap_mod_del", Category: taint.SnkLDAP, Language: rules.LangPHP, Pattern: `\bldap_mod_del(?:_ext)?\s*\(`, ObjectType: "", MethodName: "ldap_mod_del", DangerousArgs: []int{1}, Severity: rules.High, Description: "LDAP DN injection via ldap_mod_del() attribute deletion", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.ldap_rename", Category: taint.SnkLDAP, Language: rules.LangPHP, Pattern: `\bldap_rename(?:_ext)?\s*\(`, ObjectType: "", MethodName: "ldap_rename", DangerousArgs: []int{1}, Severity: rules.High, Description: "LDAP DN injection via ldap_rename() entry renaming", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},

		// Laravel framework sinks
		{ID: "php.laravel.db.raw", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `DB::raw\s*\(`, ObjectType: "DB", MethodName: "DB::raw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via Laravel DB::raw()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.laravel.whereRaw", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `->whereRaw\s*\(`, ObjectType: "Eloquent", MethodName: "whereRaw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via Eloquent whereRaw()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.laravel.selectRaw", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `->selectRaw\s*\(`, ObjectType: "Eloquent", MethodName: "selectRaw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via Eloquent selectRaw()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.laravel.orderByRaw", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `->orderByRaw\s*\(`, ObjectType: "Eloquent", MethodName: "orderByRaw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via Eloquent orderByRaw()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.laravel.blade.unescaped", Category: taint.SnkHTMLOutput, Language: rules.LangPHP, Pattern: `\{!!\s*.*\s*!!\}`, ObjectType: "", MethodName: "{!! !!}", DangerousArgs: []int{0}, Severity: rules.High, Description: "XSS via Blade unescaped output {!! !!}", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

		// Symfony / Twig template sinks
		{ID: "php.twig.raw.filter", Category: taint.SnkHTMLOutput, Language: rules.LangPHP, Pattern: `\|\s*raw\b`, ObjectType: "", MethodName: "|raw", DangerousArgs: []int{0}, Severity: rules.High, Description: "XSS via Twig |raw filter (disables escaping)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.twig.autoescape.false", Category: taint.SnkHTMLOutput, Language: rules.LangPHP, Pattern: `autoescape\s+false`, ObjectType: "", MethodName: "autoescape false", DangerousArgs: []int{-1}, Severity: rules.High, Description: "XSS via Twig autoescape disabled", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		// Symfony HttpFoundation response sinks
		{ID: "php.symfony.response", Category: taint.SnkHTMLOutput, Language: rules.LangPHP, Pattern: `new\s+Response\s*\(`, ObjectType: "Response", MethodName: "Response", DangerousArgs: []int{0}, Severity: rules.High, Description: "XSS via Symfony Response with tainted content", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.symfony.redirectresponse", Category: taint.SnkRedirect, Language: rules.LangPHP, Pattern: `new\s+RedirectResponse\s*\(`, ObjectType: "RedirectResponse", MethodName: "RedirectResponse", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via Symfony RedirectResponse with tainted URL", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},

		// CodeIgniter framework sinks
		{ID: "php.codeigniter.db.query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\$this->db->query\s*\(`, ObjectType: "CI_DB", MethodName: "query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via CodeIgniter db->query()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// Phalcon framework sinks
		// Raw SQL through the DI-injected "db" service (Phalcon\Db\Adapter):
		// $this->db->query($sql) / $this->db->execute($sql). ObjectType
		// "Phalcon\Db\Database" carries the "database" token so the tsflow
		// receiver heuristic binds the $this->db receiver to this sink.
		{ID: "php.phalcon.db.query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\$(?:this->)?db->query\s*\(`, ObjectType: "Phalcon\\Db\\Database", MethodName: "query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via Phalcon db->query() raw SQL", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.phalcon.db.execute", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\$(?:this->)?db->execute\s*\(`, ObjectType: "Phalcon\\Db\\Database", MethodName: "execute", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via Phalcon db->execute() raw SQL", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		// PHQL through the models manager: concatenating user input into a PHQL
		// string defeats PHQL's bound-parameter protection (CWE-89).
		{ID: "php.phalcon.modelsmanager.executequery", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\$(?:this->)?modelsManager->executeQuery\s*\(`, ObjectType: "modelsManager", MethodName: "executeQuery", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "PHQL injection via Phalcon modelsManager->executeQuery() with concatenated query string", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		// Reflected XSS: writing tainted data straight into the HTTP response
		// body via Phalcon\Http\Response::setContent().
		{ID: "php.phalcon.response.setcontent", Category: taint.SnkHTMLOutput, Language: rules.LangPHP, Pattern: `\$(?:this->)?response->setContent\s*\(`, ObjectType: "Response", MethodName: "setContent", DangerousArgs: []int{0}, Severity: rules.High, Description: "Reflected XSS via Phalcon response->setContent() with unescaped data", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

		// WordPress sinks
		{ID: "php.wordpress.wpdb.query", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\$wpdb->query\s*\(`, ObjectType: "wpdb", MethodName: "query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via WordPress wpdb->query()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.wordpress.wpdb.get_results", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\$wpdb->get_results\s*\(`, ObjectType: "wpdb", MethodName: "get_results", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via WordPress wpdb->get_results()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.wordpress.update_option", Category: taint.SnkTrustBoundary, Language: rules.LangPHP, Pattern: `\bupdate_option\s*\(`, ObjectType: "", MethodName: "update_option", DangerousArgs: []int{0}, Severity: rules.High, Description: "Arbitrary option overwrite via user-controlled option NAME in update_option() — the value is stored through parameterized internals (not SQLi), but a tainted option name lets an attacker overwrite arbitrary settings", CWEID: "CWE-915", OWASPCategory: "A04:2021-Insecure Design"},

		// WordPress wpdb read helpers — each accepts a raw SQL query string
		// (arg 0) and executes it; unparameterized input is SQLi. The prepare()
		// sanitizer neutralizes them.
		{ID: "php.wordpress.wpdb.get_var", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\$wpdb->get_var\s*\(`, ObjectType: "wpdb", MethodName: "get_var", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via WordPress wpdb->get_var() — executes raw SQL to retrieve a single value", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.wordpress.wpdb.get_row", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\$wpdb->get_row\s*\(`, ObjectType: "wpdb", MethodName: "get_row", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via WordPress wpdb->get_row() — executes raw SQL to retrieve a single row", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.wordpress.wpdb.get_col", Category: taint.SnkSQLQuery, Language: rules.LangPHP, Pattern: `\$wpdb->get_col\s*\(`, ObjectType: "wpdb", MethodName: "get_col", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via WordPress wpdb->get_col() — executes raw SQL to retrieve a single column", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// WordPress wp_mail($to, $subject, $message, $headers, $attachments) —
		// thin PHPMailer wrapper. Tainted $to/$subject/$headers enable CRLF
		// header injection (CWE-93).
		{ID: "php.wordpress.wp_mail", Category: taint.SnkHeader, Language: rules.LangPHP, Pattern: `\bwp_mail\s*\(`, ObjectType: "", MethodName: "wp_mail", DangerousArgs: []int{0, 1, 3}, Severity: rules.High, Description: "Email header injection via WordPress wp_mail() — tainted recipient/subject/headers enable CRLF injection", CWEID: "CWE-93", OWASPCategory: "A03:2021-Injection"},

		// WordPress template loaders — each resolves a template path and
		// require()s the file. Tainted path enables LFI (CWE-98) / path
		// traversal (CWE-22).
		{ID: "php.wordpress.load_template", Category: taint.SnkFileRead, Language: rules.LangPHP, Pattern: `\bload_template\s*\(`, ObjectType: "", MethodName: "load_template", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Local file inclusion via WordPress load_template() — require()s the supplied path", CWEID: "CWE-98", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.wordpress.locate_template", Category: taint.SnkFileRead, Language: rules.LangPHP, Pattern: `\blocate_template\s*\(`, ObjectType: "", MethodName: "locate_template", DangerousArgs: []int{0}, Severity: rules.High, Description: "Local file inclusion via WordPress locate_template() when $load=true — require()s the resolved path", CWEID: "CWE-98", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.wordpress.get_template_part", Category: taint.SnkFileRead, Language: rules.LangPHP, Pattern: `\bget_template_part\s*\(`, ObjectType: "", MethodName: "get_template_part", DangerousArgs: []int{0}, Severity: rules.High, Description: "Local file inclusion via WordPress get_template_part() — loads a tainted template slug", CWEID: "CWE-98", OWASPCategory: "A03:2021-Injection"},

		// Mail header injection
		{ID: "php.mail", Category: taint.SnkHeader, Language: rules.LangPHP, Pattern: `\bmail\s*\(`, ObjectType: "", MethodName: "mail", DangerousArgs: []int{0, 1, 3}, Severity: rules.High, Description: "Email header injection via mail()", CWEID: "CWE-93", OWASPCategory: "A03:2021-Injection"},

		// Variable injection
		{ID: "php.extract", Category: taint.SnkEval, Language: rules.LangPHP, Pattern: `\bextract\s*\(`, ObjectType: "", MethodName: "extract", DangerousArgs: []int{0}, Severity: rules.High, Description: "Variable injection via extract() overwrites local scope", CWEID: "CWE-621", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.parse_str", Category: taint.SnkEval, Language: rules.LangPHP, Pattern: `\bparse_str\s*\(`, ObjectType: "", MethodName: "parse_str", DangerousArgs: []int{0}, Severity: rules.High, Description: "Variable overwrite via parse_str() without second argument", CWEID: "CWE-621", OWASPCategory: "A03:2021-Injection"},

		// XXE (XML External Entity)
		{ID: "php.simplexml_load_string", Category: taint.SnkDeserialize, Language: rules.LangPHP, Pattern: `\bsimplexml_load_string\s*\(`, ObjectType: "", MethodName: "simplexml_load_string", DangerousArgs: []int{0}, Severity: rules.High, Description: "XXE via simplexml_load_string() with external entities", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
		{ID: "php.dom.loadxml", Category: taint.SnkDeserialize, Language: rules.LangPHP, Pattern: `->loadXML\s*\(`, ObjectType: "DOMDocument", MethodName: "loadXML", DangerousArgs: []int{0}, Severity: rules.High, Description: "XXE via DOMDocument::loadXML() with external entities", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
		{ID: "php.simplexml_load_file", Category: taint.SnkDeserialize, Language: rules.LangPHP, Pattern: `\bsimplexml_load_file\s*\(`, ObjectType: "", MethodName: "simplexml_load_file", DangerousArgs: []int{0}, Severity: rules.High, Description: "XXE via simplexml_load_file() with external entities", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},

		// Unrestricted file upload (CWE-434) — move_uploaded_file($_FILES['x']
		// ['tmp_name'], $dst) persists an uploaded file. When the extension /
		// MIME type / content of the upload isn't validated (the $_FILES tmp
		// name flows straight in, arg 0) or $dst is user-controlled (arg 1),
		// an attacker can drop a webshell. Both args are dangerous.
		{ID: "php.move_uploaded_file", Category: taint.SnkUpload, Language: rules.LangPHP, Pattern: `\bmove_uploaded_file\s*\(`, ObjectType: "", MethodName: "move_uploaded_file", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "move_uploaded_file() persisting a $_FILES upload without extension/MIME validation (or to a user-controlled path) — unrestricted file upload", CWEID: "CWE-434", OWASPCategory: "A04:2021-Insecure Design"},

		// Weak cryptographic hash (CWE-328)
		{ID: "php.crypto.md5", Category: taint.SnkCrypto, Language: rules.LangPHP, Pattern: `\bmd5\s*\(`, ObjectType: "", MethodName: "md5", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Weak MD5 hash usage (use password_hash or hash('sha256') instead)", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "php.crypto.sha1", Category: taint.SnkCrypto, Language: rules.LangPHP, Pattern: `\bsha1\s*\(`, ObjectType: "", MethodName: "sha1", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Weak SHA1 hash usage", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},

		// Insecure random (CWE-338)
		{ID: "php.crypto.rand", Category: taint.SnkCrypto, Language: rules.LangPHP, Pattern: `\brand\s*\(|\bmt_rand\s*\(`, ObjectType: "", MethodName: "rand/mt_rand", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Non-cryptographic random used for security (use random_bytes/random_int instead)", CWEID: "CWE-338", OWASPCategory: "A02:2021-Cryptographic Failures"},

		// Weak encryption (CWE-327)
		{ID: "php.crypto.mcrypt", Category: taint.SnkCrypto, Language: rules.LangPHP, Pattern: `\bmcrypt_encrypt\s*\(|\bmcrypt_decrypt\s*\(`, ObjectType: "", MethodName: "mcrypt_*", DangerousArgs: []int{0}, Severity: rules.High, Description: "Deprecated mcrypt library usage (use openssl_encrypt instead)", CWEID: "CWE-327", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "php.crypto.ecb_mode", Category: taint.SnkCrypto, Language: rules.LangPHP, Pattern: `MCRYPT_MODE_ECB|openssl_encrypt\s*\(.*\becb\b`, ObjectType: "", MethodName: "ECB mode", DangerousArgs: []int{-1}, Severity: rules.High, Description: "ECB mode cipher usage (no diffusion, use CBC/GCM)", CWEID: "CWE-327", OWASPCategory: "A02:2021-Cryptographic Failures"},
		// Weak hash / PRNG functions (CWE-328, CWE-338)
		{ID: "php.crypto.uniqid", Category: taint.SnkCrypto, Language: rules.LangPHP, Pattern: `\buniqid\s*\(`, ObjectType: "", MethodName: "uniqid", DangerousArgs: []int{-1}, Severity: rules.Medium, Description: "uniqid() is based on microtime and is not cryptographically secure — use random_bytes() for tokens", CWEID: "CWE-338", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "php.crypto.crc32", Category: taint.SnkCrypto, Language: rules.LangPHP, Pattern: `\bcrc32\s*\(`, ObjectType: "", MethodName: "crc32", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "crc32() is a checksum, not a cryptographic hash — trivially collidable for security purposes", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "php.crypto.lcg_value", Category: taint.SnkCrypto, Language: rules.LangPHP, Pattern: `\blcg_value\s*\(`, ObjectType: "", MethodName: "lcg_value", DangerousArgs: []int{-1}, Severity: rules.High, Description: "lcg_value() is a non-cryptographic linear congruential generator — use random_bytes()/random_int()", CWEID: "CWE-338", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "php.crypto.mhash", Category: taint.SnkCrypto, Language: rules.LangPHP, Pattern: `\bmhash\s*\(`, ObjectType: "", MethodName: "mhash", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "mhash() is deprecated and commonly used with broken algorithms (MHASH_MD5/SHA1/CRC32) — use hash() with sha256 or stronger", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},

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

		// --- IMAP injection (ext/imap) — CVE-2018-19518 (Roundcube), CVE-2014-9913 ---
		// imap_open's mailbox argument has the form `{host:port/options}folder`.
		// When PHP is built with imap.enable_insecure_rsh enabled (default before
		// PHP 7.3.0, still common in older deployments), the options string is
		// forwarded to the rsh/ssh helper and shell metacharacters become RCE.
		{ID: "php.imap.imap_open", Category: taint.SnkCommand, Language: rules.LangPHP, Pattern: `\bimap_open\s*\(`, ObjectType: "", MethodName: "imap_open", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "imap_open() with tainted mailbox enables IMAP option injection / RCE via rsh helper (CVE-2018-19518)", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		// imap_mail() — same SMTP/sendmail header-injection class as PHP's mail().
		// Tainted recipient/subject/additional_headers/cc/bcc allow CRLF injection
		// to forge envelope fields and inject extra MIME parts.
		{ID: "php.imap.imap_mail", Category: taint.SnkHeader, Language: rules.LangPHP, Pattern: `\bimap_mail\s*\(`, ObjectType: "", MethodName: "imap_mail", DangerousArgs: []int{0, 1, 3, 4, 5}, Severity: rules.High, Description: "Email header injection via imap_mail() — tainted to/subject/additional_headers/cc/bcc allow CRLF and SMTP envelope tampering", CWEID: "CWE-93", OWASPCategory: "A03:2021-Injection"},
		// imap_createmailbox / imap_renamemailbox parse the same {host:options}folder
		// syntax as imap_open, so user-controlled mailbox names share the option-injection risk.
		{ID: "php.imap.createmailbox", Category: taint.SnkCommand, Language: rules.LangPHP, Pattern: `\bimap_createmailbox\s*\(`, ObjectType: "", MethodName: "imap_createmailbox", DangerousArgs: []int{1}, Severity: rules.High, Description: "imap_createmailbox() with tainted mailbox name — same {host:options}folder parser as imap_open enables IMAP option injection", CWEID: "CWE-77", OWASPCategory: "A03:2021-Injection"},
		{ID: "php.imap.renamemailbox", Category: taint.SnkCommand, Language: rules.LangPHP, Pattern: `\bimap_renamemailbox\s*\(`, ObjectType: "", MethodName: "imap_renamemailbox", DangerousArgs: []int{1, 2}, Severity: rules.High, Description: "imap_renamemailbox() with tainted old/new mailbox names — same parser as imap_open enables IMAP option injection", CWEID: "CWE-77", OWASPCategory: "A03:2021-Injection"},

		// --- PHP SSH2 extension (ext/ssh2 / libssh2) ---
		// Connecting to a user-controlled host = SSH SSRF / internal pivot.
		{ID: "php.ssh2.connect", Category: taint.SnkURLFetch, Language: rules.LangPHP, Pattern: `\bssh2_connect\s*\(`, ObjectType: "", MethodName: "ssh2_connect", DangerousArgs: []int{0}, Severity: rules.High, Description: "ssh2_connect() with tainted host enables SSH SSRF / internal-network pivoting", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		// ssh2_exec(session, command, ...) runs the second arg verbatim on the remote host.
		{ID: "php.ssh2.exec", Category: taint.SnkCommand, Language: rules.LangPHP, Pattern: `\bssh2_exec\s*\(`, ObjectType: "", MethodName: "ssh2_exec", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "ssh2_exec() executes the command argument on the remote SSH server — tainted input is remote command injection", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		// ssh2_shell(session, term_type, ...) — term_type ends up in the SSH SHELL channel request.
		{ID: "php.ssh2.shell", Category: taint.SnkCommand, Language: rules.LangPHP, Pattern: `\bssh2_shell\s*\(`, ObjectType: "", MethodName: "ssh2_shell", DangerousArgs: []int{1}, Severity: rules.High, Description: "ssh2_shell() with tainted term_type — value is forwarded to the remote SSH SHELL request", CWEID: "CWE-77", OWASPCategory: "A03:2021-Injection"},
		// SCP send/recv — local_file and remote_file both reach filesystem operations on
		// either side; tainted paths enable directory traversal during transfer.
		{ID: "php.ssh2.scp_send", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\bssh2_scp_send\s*\(`, ObjectType: "", MethodName: "ssh2_scp_send", DangerousArgs: []int{1, 2}, Severity: rules.High, Description: "ssh2_scp_send() with tainted local_file or remote_file enables path traversal during SCP upload", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.ssh2.scp_recv", Category: taint.SnkFileRead, Language: rules.LangPHP, Pattern: `\bssh2_scp_recv\s*\(`, ObjectType: "", MethodName: "ssh2_scp_recv", DangerousArgs: []int{1}, Severity: rules.High, Description: "ssh2_scp_recv() with tainted remote_file argument enables remote-side path traversal during SCP download", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// --- phpseclib3 (phpseclib\Net\SSH2 / phpseclib\Net\SFTP) — the dominant
		// pure-PHP SSH/SFTP library (used by league/flysystem-sftp, Symfony, etc.).
		// new SSH2($host) connecting to a user-controlled host = SSH SSRF / pivot.
		// $ssh->exec($cmd) is already covered by the generic php.exec sink (ObjectType
		// "" / MethodName "exec"), so it is intentionally not duplicated here.
		{ID: "php.phpseclib.ssh2.connect", Category: taint.SnkURLFetch, Language: rules.LangPHP, Pattern: `new\s+\\?(?:phpseclib3?\\Net\\)?SSH2\s*\(`, ObjectType: "SSH2", MethodName: "SSH2", DangerousArgs: []int{0}, Severity: rules.High, Description: "phpseclib new SSH2($host) with a tainted hostname connects an SSH client to an attacker-chosen host (SSH SSRF / internal-network pivoting)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		// SFTP path-traversal sinks — the remote path argument(s) end up in SFTP
		// filesystem operations on the remote server; tainted input enables directory
		// traversal (read, write, delete, rename, chmod/chown/chgrp, listing).
		{ID: "php.phpseclib.sftp.get", Category: taint.SnkFileRead, Language: rules.LangPHP, Pattern: `\$sftp\w*\s*->get\s*\(`, ObjectType: "SFTP", MethodName: "get", DangerousArgs: []int{0}, Severity: rules.High, Description: "phpseclib SFTP::get($remote_file) with a tainted remote path enables path traversal / arbitrary remote-file disclosure", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.phpseclib.sftp.put", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\$sftp\w*\s*->put\s*\(`, ObjectType: "SFTP", MethodName: "put", DangerousArgs: []int{0}, Severity: rules.High, Description: "phpseclib SFTP::put($remote_file, ...) with a tainted remote path enables path traversal during SFTP upload", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.phpseclib.sftp.delete", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\$sftp\w*\s*->delete\s*\(`, ObjectType: "SFTP", MethodName: "delete", DangerousArgs: []int{0}, Severity: rules.High, Description: "phpseclib SFTP::delete($path) with a tainted remote path enables destructive path traversal (arbitrary remote-file deletion)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.phpseclib.sftp.rmdir", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\$sftp\w*\s*->rmdir\s*\(`, ObjectType: "SFTP", MethodName: "rmdir", DangerousArgs: []int{0}, Severity: rules.High, Description: "phpseclib SFTP::rmdir($dir) with a tainted remote path enables directory traversal during remote directory removal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.phpseclib.sftp.chmod", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\$sftp\w*\s*->chmod\s*\(`, ObjectType: "SFTP", MethodName: "chmod", DangerousArgs: []int{1}, Severity: rules.High, Description: "phpseclib SFTP::chmod($mode, $filename) with a tainted filename enables path traversal when changing remote permissions", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.phpseclib.sftp.chown", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\$sftp\w*\s*->chown\s*\(`, ObjectType: "SFTP", MethodName: "chown", DangerousArgs: []int{0}, Severity: rules.High, Description: "phpseclib SFTP::chown($filename, $uid) with a tainted filename enables path traversal when changing remote ownership", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.phpseclib.sftp.chgrp", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\$sftp\w*\s*->chgrp\s*\(`, ObjectType: "SFTP", MethodName: "chgrp", DangerousArgs: []int{0}, Severity: rules.High, Description: "phpseclib SFTP::chgrp($filename, $gid) with a tainted filename enables path traversal when changing remote group", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.phpseclib.sftp.touch", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\$sftp\w*\s*->touch\s*\(`, ObjectType: "SFTP", MethodName: "touch", DangerousArgs: []int{0}, Severity: rules.High, Description: "phpseclib SFTP::touch($filename, ...) with a tainted filename enables path traversal when creating/updating remote files", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.phpseclib.sftp.truncate", Category: taint.SnkFileWrite, Language: rules.LangPHP, Pattern: `\$sftp\w*\s*->truncate\s*\(`, ObjectType: "SFTP", MethodName: "truncate", DangerousArgs: []int{0}, Severity: rules.High, Description: "phpseclib SFTP::truncate($filename, $new_size) with a tainted filename enables path traversal when truncating remote files", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.phpseclib.sftp.nlist", Category: taint.SnkFileRead, Language: rules.LangPHP, Pattern: `\$sftp\w*\s*->nlist\s*\(`, ObjectType: "SFTP", MethodName: "nlist", DangerousArgs: []int{0}, Severity: rules.High, Description: "phpseclib SFTP::nlist($dir) with a tainted remote path enables path traversal / remote directory enumeration", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "php.phpseclib.sftp.rawlist", Category: taint.SnkFileRead, Language: rules.LangPHP, Pattern: `\$sftp\w*\s*->rawlist\s*\(`, ObjectType: "SFTP", MethodName: "rawlist", DangerousArgs: []int{0}, Severity: rules.High, Description: "phpseclib SFTP::rawlist($dir) with a tainted remote path enables path traversal / remote directory enumeration", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// Log injection (CWE-117)
		{ID: "php.error_log", Category: taint.SnkLog, Language: rules.LangPHP, Pattern: `\berror_log\s*\(`, ObjectType: "", MethodName: "error_log", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "error_log with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "php.syslog", Category: taint.SnkLog, Language: rules.LangPHP, Pattern: `\bsyslog\s*\(`, ObjectType: "", MethodName: "syslog", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "syslog with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "php.laravel.log.info", Category: taint.SnkLog, Language: rules.LangPHP, Pattern: `Log::(?:info|warning|error|debug|critical|emergency|notice|alert)\s*\(`, ObjectType: "Log", MethodName: "Log::*", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Laravel Log facade with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "php.monolog.log", Category: taint.SnkLog, Language: rules.LangPHP, Pattern: `->(?:info|warning|error|debug|critical|emergency|notice|alert)\s*\(`, ObjectType: "Monolog\\Logger", MethodName: "Logger->*", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Monolog logger with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},

		// --- File read / path traversal (CWE-22) ---
		{
			ID:            "php.file",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPHP,
			Pattern:       `(?:^|[^>\w])file\s*\(`,
			ObjectType:    "",
			MethodName:    "file",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "file() reads entire file into array with user-controlled path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "php.readfile",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPHP,
			Pattern:       `\breadfile\s*\(`,
			ObjectType:    "",
			MethodName:    "readfile",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "readfile() outputs file contents with user-controlled path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "php.highlight_file",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPHP,
			Pattern:       `\b(?:highlight_file|show_source)\s*\(`,
			ObjectType:    "",
			MethodName:    "highlight_file/show_source",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "highlight_file()/show_source() exposes PHP source code with user-controlled path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "php.parse_ini_file",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPHP,
			Pattern:       `\bparse_ini_file\s*\(`,
			ObjectType:    "",
			MethodName:    "parse_ini_file",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "parse_ini_file() reads config files with user-controlled path (information disclosure)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "php.scandir",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPHP,
			Pattern:       `\bscandir\s*\(`,
			ObjectType:    "",
			MethodName:    "scandir",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "scandir() directory listing with user-controlled path (information disclosure)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "php.glob",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPHP,
			Pattern:       `\bglob\s*\(`,
			ObjectType:    "",
			MethodName:    "glob",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "glob() pattern-based directory listing with user-controlled pattern (information disclosure)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "php.getimagesize",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPHP,
			Pattern:       `\bgetimagesize\s*\(`,
			ObjectType:    "",
			MethodName:    "getimagesize",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "getimagesize() reads image metadata with user-controlled path (SSRF/path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "php.splfileobject",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPHP,
			Pattern:       `new\s+SplFileObject\s*\(`,
			ObjectType:    "SplFileObject",
			MethodName:    "SplFileObject",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SplFileObject constructor with user-controlled path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "php.file_exists",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPHP,
			Pattern:       `\bfile_exists\s*\(`,
			ObjectType:    "",
			MethodName:    "file_exists",
			DangerousArgs: []int{0},
			Severity:      rules.Low,
			Description:   "file_exists() with user-controlled path (file existence probing)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "php.is_file",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPHP,
			Pattern:       `\b(?:is_file|is_readable|is_dir|is_writable)\s*\(`,
			ObjectType:    "",
			MethodName:    "is_file/is_readable/is_dir/is_writable",
			DangerousArgs: []int{0},
			Severity:      rules.Low,
			Description:   "File check functions with user-controlled path (filesystem probing)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- File write operations (CWE-22) ---
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
			Pattern:       `(?:^|[^>\w])link\s*\(`,
			ObjectType:    "",
			MethodName:    "link",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Hard link creation with potentially tainted paths (external control of file name)",
			CWEID:         "CWE-73",
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
			Description:   "File rename with potentially tainted paths (external control of file name)",
			CWEID:         "CWE-73",
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
			Description:   "File copy with potentially tainted paths (external control of file name)",
			CWEID:         "CWE-73",
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
		// --- Symfony ExpressionLanguage injection (CWE-94 / CWE-917) ---
		// symfony/expression-language compiles and evaluates a string in its own
		// mini-language. evaluate($expr) interprets the expression immediately;
		// compile($expr) emits PHP source. The grammar exposes object method
		// calls, constants, and array/property access, so a tainted expression is
		// code execution (e.g. `service('...').someMethod()`, `constant('...')`).
		// Used pervasively in Symfony: Security expression voters / @Security and
		// #[IsGranted] attributes, the Validator @Expression / Expression
		// constraint, routing condition: and access_control allow_if, and config
		// "@=" expressions. The receiver is conventionally $expressionLanguage /
		// $expression / $el. There is NO sanitizer — the only safe usage is a
		// static, developer-authored expression string, so a tainted argument is
		// always reportable. CVE context: CVE-2017-16652 (Symfony EL access
		// control) and numerous SSTI-to-RCE chains in Symfony apps.
		{
			ID:            "php.symfony.expressionlanguage.evaluate",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `(?:ExpressionLanguage|\$expressionLanguage|\$expression|\$expressionEngine|\$el)\s*->\s*evaluate\s*\(`,
			ObjectType:    "ExpressionLanguage",
			MethodName:    "evaluate",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Symfony ExpressionLanguage::evaluate() runs a tainted expression in the Expression Language grammar — method calls/constants make this code execution (CWE-94/917). Never evaluate user input; restrict to a static, developer-authored expression.",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.symfony.expressionlanguage.compile",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `(?:ExpressionLanguage|\$expressionLanguage|\$expression|\$expressionEngine|\$el)\s*->\s*compile\s*\(`,
			ObjectType:    "ExpressionLanguage",
			MethodName:    "compile",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Symfony ExpressionLanguage::compile() emits PHP source from a tainted expression string (CWE-94/917) — compiling attacker input is code injection. Restrict to a static expression.",
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
		// --- Dynamic callable STRING in a higher-order callback slot (CWE-95).
		// PHP's array iteration builtins accept the callback as a *string*
		// function name; when that string is attacker-controlled it is an
		// arbitrary-function-call (`array_map($_GET['fn'], $items)` →
		// `system`). DangerousArgs is scoped to ONLY the callback-name
		// position — NEVER the data array — so the dominant literal-callback
		// idiom (`array_map('intval', $a)`) carries no taint and never fires;
		// the flow records only when the callable string itself is tainted.
		// Distinct from php.call_user_func (the call_user_func family);
		// these are the array_* / usort / *_callback callback slots Semgrep
		// flags but Batou lacked.
		{
			ID:            "php.array_map.callback",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `\barray_map\s*\(`,
			ObjectType:    "",
			MethodName:    "array_map",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Arbitrary function call via tainted callable string in array_map() callback position (arg 0)",
			CWEID:         "CWE-95",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.array_filter.callback",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `\barray_filter\s*\(`,
			ObjectType:    "",
			MethodName:    "array_filter",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "Arbitrary function call via tainted callable string in array_filter() callback position (arg 1)",
			CWEID:         "CWE-95",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.usort.callback",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `\b(?:usort|uasort|uksort)\s*\(`,
			ObjectType:    "",
			MethodName:    "usort",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "Arbitrary function call via tainted callable string in usort()/uasort()/uksort() comparator position (arg 1)",
			CWEID:         "CWE-95",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.array_walk.callback",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `\barray_walk(?:_recursive)?\s*\(`,
			ObjectType:    "",
			MethodName:    "array_walk",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "Arbitrary function call via tainted callable string in array_walk()/array_walk_recursive() callback position (arg 1)",
			CWEID:         "CWE-95",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.preg_replace_callback.callable",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `\bpreg_replace_callback(?:_array)?\s*\(`,
			ObjectType:    "",
			MethodName:    "preg_replace_callback",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "Arbitrary function call via tainted callable string in preg_replace_callback() callback position (arg 1)",
			CWEID:         "CWE-95",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.register_shutdown_function.callback",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `\bregister_shutdown_function\s*\(`,
			ObjectType:    "",
			MethodName:    "register_shutdown_function",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Arbitrary function call via tainted callable string in register_shutdown_function() callback position (arg 0)",
			CWEID:         "CWE-95",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Reflection-based instantiation / invocation (CWE-470). The
		// ReflectionClass / ReflectionMethod / ReflectionFunction objects let
		// code construct any class or invoke any method by NAME. When the
		// class/method name traces to a request source this is unsafe
		// reflection (the runtime equivalent of `new $tainted()`). These sinks
		// are RECEIVER-TYPED on the Reflection* object so they never collide
		// with an unrelated ->newInstance()/->invoke() on some other class —
		// the producer must resolve the receiver to a Reflection* type for the
		// flow to record. The tainted class/method name flows into the
		// Reflection* constructor and then into the realising call; marking
		// these invocation methods catches the gadget at the point the
		// object/method is actually instantiated or invoked.
		{
			ID:            "php.reflection.newInstance",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `->newInstance(?:Args|WithoutConstructor)?\s*\(`,
			ObjectType:    "ReflectionClass",
			MethodName:    "newInstance",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Unsafe reflection: ReflectionClass::newInstance()/newInstanceArgs() realises an object whose class name was attacker-controlled — arbitrary class instantiation / POP-gadget trigger (CWE-470)",
			CWEID:         "CWE-470",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.reflectionmethod.invoke",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `->invoke(?:Args)?\s*\(`,
			ObjectType:    "ReflectionMethod",
			MethodName:    "invoke",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Unsafe reflection: ReflectionMethod::invoke()/invokeArgs() calls a method whose name was attacker-controlled — arbitrary method invocation (CWE-470)",
			CWEID:         "CWE-470",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.reflectionfunction.invoke",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `->invoke(?:Args)?\s*\(`,
			ObjectType:    "ReflectionFunction",
			MethodName:    "invoke",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Unsafe reflection: ReflectionFunction::invoke()/invokeArgs() calls a function whose name was attacker-controlled — arbitrary function invocation (CWE-470)",
			CWEID:         "CWE-470",
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
		{
			ID:            "php.twig.createtemplate",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPHP,
			Pattern:       `->createTemplate\s*\(`,
			ObjectType:    "Twig\\Environment",
			MethodName:    "createTemplate",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Twig Environment::createTemplate() compiles a tainted string as a template (SSTI; CVE-2022-23614 context)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.twig.display",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPHP,
			Pattern:       `->display\s*\(`,
			ObjectType:    "Twig\\Environment",
			MethodName:    "display",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Twig Environment::display() renders a tainted template name (SSTI / template-name injection)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.laravel.blade.compilestring",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPHP,
			Pattern:       `Blade::compileString\s*\(`,
			ObjectType:    "Blade",
			MethodName:    "Blade::compileString",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Laravel Blade::compileString() compiles a tainted string to PHP (SSTI / RCE)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.laravel.view.make",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPHP,
			Pattern:       `View::make\s*\(`,
			ObjectType:    "View",
			MethodName:    "View::make",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Laravel View::make() with tainted view name (template-name injection)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.latte.rendertostring",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPHP,
			Pattern:       `->renderToString\s*\(`,
			ObjectType:    "Latte\\Engine",
			MethodName:    "renderToString",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Nette Latte Engine::renderToString() with tainted template path (SSTI)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- XPath Injection (CWE-643) ---
		{
			ID:            "php.domxpath.query",
			Category:      taint.SnkXPath,
			Language:      rules.LangPHP,
			Pattern:       `DOMXPath[^;{]*->query\s*\(`,
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
			Pattern:       `DOMXPath[^;{]*->evaluate\s*\(`,
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
		{
			ID:            "php.symfony.crawler.filterxpath",
			Category:      taint.SnkXPath,
			Language:      rules.LangPHP,
			Pattern:       `->filterXPath\s*\(`,
			ObjectType:    "Crawler",
			MethodName:    "filterXPath",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Symfony DomCrawler filterXPath with potentially tainted expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.symfony.crawler.evaluate",
			Category:      taint.SnkXPath,
			Language:      rules.LangPHP,
			Pattern:       `(?:Crawler|\$crawler)[^;{]*->evaluate\s*\(`,
			ObjectType:    "Crawler",
			MethodName:    "evaluate",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Symfony DomCrawler evaluate with potentially tainted XPath expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- XSLT Injection (CWE-91) ---
		// PHP ships the XSL extension (ext/xsl) which exposes XSLTProcessor.
		// An attacker-controlled stylesheet can read local files via document(),
		// exfiltrate data via xsl:include/xsl:import, and (when registerPHPFunctions
		// is enabled) invoke arbitrary PHP functions via php:function().
		// CVE references: CVE-2018-5712 (PHP XSL RCE), CVE-2015-8478 (libxslt).
		{
			ID:            "php.xsl.xsltprocessor.importstylesheet",
			Category:      taint.SnkXPath,
			Language:      rules.LangPHP,
			Pattern:       `->importStyle[Ss]heet\s*\(`,
			ObjectType:    "XSLTProcessor",
			MethodName:    "importStyleSheet/importStylesheet",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XSLTProcessor::importStyleSheet with tainted DOMDocument — attacker-controlled stylesheet enables file read, SSRF, and (with registerPHPFunctions) RCE",
			CWEID:         "CWE-91",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.xsl.xsltprocessor.transformtoxml",
			Category:      taint.SnkXPath,
			Language:      rules.LangPHP,
			Pattern:       `->transformToX[mM][lL]\s*\(`,
			ObjectType:    "XSLTProcessor",
			MethodName:    "transformToXml/transformToXML",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XSLTProcessor::transformToXml with tainted input document — XSLT transformation of attacker-shaped XML",
			CWEID:         "CWE-91",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.xsl.xsltprocessor.transformtodoc",
			Category:      taint.SnkXPath,
			Language:      rules.LangPHP,
			Pattern:       `->transformToDoc\s*\(`,
			ObjectType:    "XSLTProcessor",
			MethodName:    "transformToDoc",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XSLTProcessor::transformToDoc with tainted input document — XSLT transformation of attacker-shaped XML",
			CWEID:         "CWE-91",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.xsl.xsltprocessor.transformtouri",
			Category:      taint.SnkXPath,
			Language:      rules.LangPHP,
			Pattern:       `->transformToU[rR][iI]\s*\(`,
			ObjectType:    "XSLTProcessor",
			MethodName:    "transformToUri/transformToURI",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "XSLTProcessor::transformToUri with tainted output URI — arbitrary file/network write via XSLT transformation target",
			CWEID:         "CWE-91",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Doctrine SQL injection (CWE-89) ---
		{
			ID:            "php.doctrine.nativequery",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->createNativeQuery\(`,
			ObjectType:    "EntityManager",
			MethodName:    "createNativeQuery",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine createNativeQuery() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.dqlquery",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->createQuery\(`,
			ObjectType:    "EntityManager",
			MethodName:    "createQuery",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine createQuery() DQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.connection.exec",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->executeStatement\(`,
			ObjectType:    "Connection",
			MethodName:    "executeStatement",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine Connection->executeStatement() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Doctrine ORM/DBAL QueryBuilder string-injection (CWE-89) ---
		// QueryBuilder is the recommended Doctrine query API, but where()/
		// andWhere()/orWhere()/having()/andHaving()/orHaving() take a raw
		// DQL/SQL fragment STRING. The safe idiom binds parameters with named
		// placeholders + ->setParameter() (the existing php sanitizer); the
		// dangerous idiom concatenates request data straight into the fragment
		// (`$qb->where("u.name = '".$_GET['n']."'")`), which is SQL injection
		// regardless of the QueryBuilder wrapper. Semgrep flags this as
		// doctrine-orm-dangerous-query / doctrine-dbal-dangerous-query; Batou had
		// the create*Query sinks but not the QueryBuilder fragment slots. The
		// ->setParameter() sanitizer keeps the placeholder-bound idiom clean, so
		// only concatenated/tainted fragments flow here. The receiver is
		// conventionally $qb / $queryBuilder / $builder (QueryBuilder ObjectType
		// prefix-matches $queryBuilder; the Pattern admits the $qb/$builder
		// shorthand receivers explicitly).
		{
			ID:            "php.doctrine.querybuilder.where",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `(?:QueryBuilder|\$qb|\$queryBuilder|\$builder)\s*->\s*(?:and|or)?[wW]here\s*\(`,
			ObjectType:    "QueryBuilder",
			MethodName:    "where/andWhere/orWhere",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Doctrine QueryBuilder where()/andWhere()/orWhere() with a tainted DQL/SQL fragment string — concatenating request data into the predicate is SQL injection (CWE-89). Use a named placeholder bound with ->setParameter() instead.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.querybuilder.having",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `(?:QueryBuilder|\$qb|\$queryBuilder|\$builder)\s*->\s*(?:and|or)?[hH]aving\s*\(`,
			ObjectType:    "QueryBuilder",
			MethodName:    "having/andHaving/orHaving",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Doctrine QueryBuilder having()/andHaving()/orHaving() with a tainted DQL/SQL fragment string — concatenating request data into the HAVING clause is SQL injection (CWE-89). Bind a named placeholder with ->setParameter() instead.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Doctrine DBAL Connection modern fetch/iterate/execute methods (CWE-89) ---
		// Doctrine DBAL is the most-used PHP database abstraction (Symfony, API Platform,
		// Sylius, Akeneo). Connection exposes SQL execution and result-fetching methods
		// that all take a raw SQL string at arg 0. Tainted SQL into any of these is SQLi
		// regardless of whether placeholder bindings are used — placeholders bind parameter
		// VALUES, not the SQL string itself. Matches receivers like $conn, $connection,
		// $this->connection via the Connection ObjectType prefix-abbreviation heuristic.
		{
			ID:            "php.doctrine.connection.executequery",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->executeQuery\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "executeQuery",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine DBAL Connection->executeQuery() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.connection.fetchallassociative",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->fetchAllAssociative\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "fetchAllAssociative",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine DBAL Connection->fetchAllAssociative() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.connection.fetchassociative",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->fetchAssociative\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "fetchAssociative",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine DBAL Connection->fetchAssociative() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.connection.fetchallnumeric",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->fetchAllNumeric\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "fetchAllNumeric",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine DBAL Connection->fetchAllNumeric() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.connection.fetchnumeric",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->fetchNumeric\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "fetchNumeric",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine DBAL Connection->fetchNumeric() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.connection.fetchallkeyvalue",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->fetchAllKeyValue\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "fetchAllKeyValue",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine DBAL Connection->fetchAllKeyValue() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.connection.fetchallassociativeindexed",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->fetchAllAssociativeIndexed\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "fetchAllAssociativeIndexed",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine DBAL Connection->fetchAllAssociativeIndexed() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.connection.fetchone",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->fetchOne\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "fetchOne",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine DBAL Connection->fetchOne() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.connection.fetchfirstcolumn",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->fetchFirstColumn\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "fetchFirstColumn",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine DBAL Connection->fetchFirstColumn() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.connection.iterateassociative",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->iterateAssociative\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "iterateAssociative",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine DBAL Connection->iterateAssociative() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.connection.iteratenumeric",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->iterateNumeric\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "iterateNumeric",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine DBAL Connection->iterateNumeric() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.connection.iteratecolumn",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->iterateColumn\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "iterateColumn",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine DBAL Connection->iterateColumn() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.doctrine.connection.iteratekeyvalue",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `->iterateKeyValue\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "iterateKeyValue",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Doctrine DBAL Connection->iterateKeyValue() raw SQL with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- NoSQL Injection / MongoDB (CWE-943) ---
		// mongodb/mongodb library (Collection methods)
		{
			ID:            "php.mongodb.find",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->find\s*\(`,
			ObjectType:    "",
			MethodName:    "find",
			DangerousArgs: []int{0},
			// Bare `find` collides with Laravel Eloquent's `->find($id)` PK
			// lookup (scalar, parameterized, safe). A MongoDB filter is a
			// container (array); require that shape so the Eloquent scalar
			// form drops out without firing a NoSQL-injection false positive.
			RequiresArgShape: taint.ArgShapeContainer,
			Severity:         rules.High,
			Description:      "MongoDB find with user-controlled query filter (NoSQL injection)",
			CWEID:            "CWE-943",
			OWASPCategory:    "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.findone",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->findOne\s*\(`,
			ObjectType:    "",
			MethodName:    "findOne",
			DangerousArgs: []int{0},
			// Same Eloquent `->findOne($id)` collision as php.mongodb.find.
			RequiresArgShape: taint.ArgShapeContainer,
			Severity:         rules.Critical,
			Description:      "MongoDB findOne with user-controlled query filter (NoSQL injection)",
			CWEID:            "CWE-943",
			OWASPCategory:    "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.findoneandupdate",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->findOneAndUpdate\s*\(`,
			ObjectType:    "",
			MethodName:    "findOneAndUpdate",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MongoDB findOneAndUpdate with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.findoneandreplace",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->findOneAndReplace\s*\(`,
			ObjectType:    "",
			MethodName:    "findOneAndReplace",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MongoDB findOneAndReplace with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.findoneanddelete",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->findOneAndDelete\s*\(`,
			ObjectType:    "",
			MethodName:    "findOneAndDelete",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MongoDB findOneAndDelete with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.updateone",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->updateOne\s*\(`,
			ObjectType:    "",
			MethodName:    "updateOne",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MongoDB updateOne with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.updatemany",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->updateMany\s*\(`,
			ObjectType:    "",
			MethodName:    "updateMany",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MongoDB updateMany with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.deleteone",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->deleteOne\s*\(`,
			ObjectType:    "",
			MethodName:    "deleteOne",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MongoDB deleteOne with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.deletemany",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->deleteMany\s*\(`,
			ObjectType:    "",
			MethodName:    "deleteMany",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MongoDB deleteMany with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.insertone",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->insertOne\s*\(`,
			ObjectType:    "",
			MethodName:    "insertOne",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoDB insertOne with user-controlled document (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.insertmany",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->insertMany\s*\(`,
			ObjectType:    "",
			MethodName:    "insertMany",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoDB insertMany with user-controlled documents (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.aggregate",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->aggregate\s*\(`,
			ObjectType:    "",
			MethodName:    "aggregate",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoDB aggregate pipeline with user-controlled stages (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.countdocuments",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->countDocuments\s*\(`,
			ObjectType:    "",
			MethodName:    "countDocuments",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MongoDB countDocuments with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.distinct",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->distinct\s*\(`,
			ObjectType:    "",
			MethodName:    "distinct",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "MongoDB distinct with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.replaceone",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->replaceOne\s*\(`,
			ObjectType:    "",
			MethodName:    "replaceOne",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MongoDB replaceOne with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		// MongoDB low-level driver (MongoDB\Driver\Manager)
		{
			ID:            "php.mongodb.driver.executequery",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->executeQuery\s*\(`,
			ObjectType:    "",
			MethodName:    "executeQuery",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "MongoDB Driver executeQuery with user-controlled query (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.driver.executecommand",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->executeCommand\s*\(`,
			ObjectType:    "",
			MethodName:    "executeCommand",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "MongoDB Driver executeCommand with user-controlled command (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mongodb.driver.executebulkwrite",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->executeBulkWrite\s*\(`,
			ObjectType:    "",
			MethodName:    "executeBulkWrite",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "MongoDB Driver executeBulkWrite with user-controlled operations (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Trust boundary violations (CWE-501) ---
		{
			ID:            "php.session.set_save_handler",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPHP,
			Pattern:       `\bsession_set_save_handler\s*\(`,
			ObjectType:    "",
			MethodName:    "session_set_save_handler",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Custom session save handler with tainted callback (trust boundary violation)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "php.ini_set.session",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPHP,
			Pattern:       `\bini_set\s*\(\s*['"]session\.`,
			ObjectType:    "",
			MethodName:    "ini_set",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "Modifying session configuration with tainted value via ini_set()",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "php.session.regenerate_id",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPHP,
			Pattern:       `\bsession_id\s*\([^)]+\)`,
			ObjectType:    "",
			MethodName:    "session_id",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Setting session ID with tainted value enables session fixation",
			CWEID:         "CWE-384",
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
		},
		{
			ID:            "php.session.name",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPHP,
			Pattern:       `\bsession_name\s*\([^)]+\)`,
			ObjectType:    "",
			MethodName:    "session_name",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Setting session name with tainted value (trust boundary violation)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "php.session.save_path",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPHP,
			Pattern:       `\bsession_save_path\s*\([^)]+\)`,
			ObjectType:    "",
			MethodName:    "session_save_path",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Setting session save path with tainted value (path injection)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "php.putenv",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPHP,
			Pattern:       `\bputenv\s*\(`,
			ObjectType:    "",
			MethodName:    "putenv",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Setting environment variable with tainted value (trust boundary violation)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "php.define",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPHP,
			Pattern:       `\bdefine\s*\(`,
			ObjectType:    "",
			MethodName:    "define",
			DangerousArgs: []int{1},
			Severity:      rules.Medium,
			Description:   "Defining runtime constant with tainted value (trust boundary violation)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},

		// --- SSRF additional (CWE-918) ---
		{
			ID:            "php.get_headers",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPHP,
			Pattern:       `\bget_headers\s*\(`,
			ObjectType:    "",
			MethodName:    "get_headers",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via get_headers() with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "php.ftp_connect",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPHP,
			Pattern:       `\bftp_connect\s*\(`,
			ObjectType:    "",
			MethodName:    "ftp_connect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via ftp_connect() with tainted hostname",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "php.fsockopen",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPHP,
			Pattern:       `\bfsockopen\s*\(`,
			ObjectType:    "",
			MethodName:    "fsockopen",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via fsockopen() with tainted hostname",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- Log injection additional (CWE-117) ---
		{
			ID:            "php.trigger_error",
			Category:      taint.SnkLog,
			Language:      rules.LangPHP,
			Pattern:       `\btrigger_error\s*\(`,
			ObjectType:    "",
			MethodName:    "trigger_error",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Log injection via trigger_error() with tainted message",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},

		// --- Drupal 10+ sinks ---
		{
			ID:            "php.drupal.db_query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\bdb_query\s*\(`,
			ObjectType:    "",
			MethodName:    "db_query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Drupal legacy db_query() with tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.drupal.database.query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `Drupal::database\s*\(\s*\)->query\s*\(`,
			ObjectType:    "Connection",
			MethodName:    "query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Drupal database connection raw query with tainted SQL",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.drupal.markup.create",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPHP,
			Pattern:       `Markup::create\s*\(`,
			ObjectType:    "Markup",
			MethodName:    "Markup::create",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Drupal Markup::create() bypasses Twig auto-escaping — XSS if tainted",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.drupal.db_select",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\bdb_select\s*\(`,
			ObjectType:    "",
			MethodName:    "db_select",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Drupal 7 legacy db_select() — table name from tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- JWT signature-verification bypass (CWE-347) ---
		//
		// namshi/jose and firebase/php-jwt expose APIs that return JWT
		// claims WITHOUT verifying the cryptographic signature (or with
		// alg=none explicitly allowed). Any attacker who controls the
		// token string can forge arbitrary claims unless a separate
		// signature verification step runs before the claims are trusted.
		{
			ID:            "php.jwt.namshi.simplejws.load",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPHP,
			Pattern:       `SimpleJWS::load\s*\(`,
			ObjectType:    "SimpleJWS",
			MethodName:    "SimpleJWS::load",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "namshi/jose SimpleJWS::load() parses the JWT without verifying the signature; the resulting object must be passed through ->isValid($publicKey, 'RS256') before any claim is trusted",
			CWEID:         "CWE-347",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "php.jwt.namshi.jws.load",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPHP,
			Pattern:       `\bJWS::load\s*\(`,
			ObjectType:    "JWS",
			MethodName:    "JWS::load",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "namshi/jose JWS::load() parses the JWS without verifying the signature (base class of SimpleJWS); use ->verify($publicKey, $alg) before exposing claims",
			CWEID:         "CWE-347",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "php.jwt.firebase.decode.none_algo",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPHP,
			Pattern:       `JWT::decode\s*\([^)]*['"]none['"]`,
			ObjectType:    "JWT",
			MethodName:    "JWT::decode",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "firebase/php-jwt JWT::decode() invoked with 'none' in the allowed-algorithms list — tokens are accepted without any signature and claims are attacker-controlled (CVE-2015-9235 class)",
			CWEID:         "CWE-347",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// --- Elasticsearch / OpenSearch query-DSL + Painless script injection ---
		// Official PHP clients (elastic/elasticsearch-php, opensearch-project/opensearch-php)
		// share the same API surface: $client->method(['index' => ..., 'body' => [...]]).
		// Tainted body values allow DSL injection (CWE-943) and, for endpoints that
		// accept a 'script' field, Painless/Mustache code execution on the cluster
		// (CWE-94). Generic names like ->search / ->count / ->index are intentionally
		// NOT added here — they FP on non-ES collections; only ES-distinctive method
		// names are listed. Mirrors py.elasticsearch.* coverage for the PHP ecosystem.
		//
		// Refs: https://www.elastic.co/guide/en/elasticsearch/painless/current/painless-execute-api.html
		//       https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-scripting-security.html
		//       CVE-2014-3120 (dynamic script RCE class — same injection pattern still
		//       applies today when tainted input is concatenated into script.source or
		//       query_string.query instead of passed via the params map).
		{
			ID:            "php.elasticsearch.msearch",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->msearch\s*\(`,
			ObjectType:    "",
			MethodName:    "msearch",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Elasticsearch msearch() NDJSON body contains alternating header/query objects — a tainted body permits per-shard DSL injection and cross-index data exfiltration; build the body from typed arrays and pass user values via the params map",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.elasticsearch.deletebyquery",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->deleteByQuery\s*\(`,
			ObjectType:    "",
			MethodName:    "deleteByQuery",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Elasticsearch deleteByQuery() with tainted query DSL can delete documents outside the intended scope (bulk destructive op); bind user values via the params map rather than concatenating into the query",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.elasticsearch.updatebyquery",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `->updateByQuery\s*\(`,
			ObjectType:    "",
			MethodName:    "updateByQuery",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Elasticsearch updateByQuery() body accepts a 'script' field (Painless) and a 'query' DSL — a tainted source allows arbitrary code execution on the ES cluster and mass document mutation outside the intended scope; pass user values via script.params rather than script.source",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.elasticsearch.scriptspainlessexecute",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `->scriptsPainlessExecute\s*\(`,
			ObjectType:    "",
			MethodName:    "scriptsPainlessExecute",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Elasticsearch scriptsPainlessExecute() directly evaluates a Painless script body on the cluster — a tainted source is arbitrary code execution on the ES node; never concatenate user input into script.source, pass values via script.params",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.elasticsearch.putscript",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `->putScript\s*\(`,
			ObjectType:    "",
			MethodName:    "putScript",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Elasticsearch putScript() stores a tainted Painless/Mustache script body — later invocations execute the attacker-supplied code on the ES cluster (persistent RCE); only register stored scripts from trusted sources",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.elasticsearch.reindex",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->reindex\s*\(`,
			ObjectType:    "",
			MethodName:    "reindex",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Elasticsearch reindex() accepts a source.query DSL — a tainted query selects arbitrary documents to copy across indices (cross-index data exposure, bulk write amplification); pass user values via params and restrict source.index",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.elasticsearch.searchtemplate",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `->searchTemplate\s*\(`,
			ObjectType:    "",
			MethodName:    "searchTemplate",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Elasticsearch searchTemplate() renders a Mustache template on the cluster — a tainted template source permits template injection that in turn invokes stored Painless scripts; only bind user values through the template 'params' map, never into 'source'",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Neo4j Cypher Injection (CWE-943) ---
		// laudis/neo4j-php-client (formerly graphaware/neo4j-php-client) is the
		// de-facto PHP Neo4j driver. ClientInterface, SessionInterface, and
		// TransactionInterface all expose run($cypher, $params, $alias?), and
		// Statement::create($cypher, $params) is the value-object factory used
		// by runStatement()/runStatements(). PHP "$var" string interpolation
		// or string concatenation into the Cypher text enables Cypher injection
		// — pass user values via the $params associative array and reference
		// them as $name in the Cypher (e.g. "MATCH (n) WHERE n.name = $name").
		// graphaware/neo4j-php-client (legacy) additionally exposes
		// ->sendCypherQuery($query, $params) on the same client.
		// Mirrors py.neo4j.*, kotlin.neo4j.*, csharp.neo4j.*, rust.neo4rs.*.
		// Refs: https://neo4j.com/developer/kb/protecting-against-cypher-injection/
		//       https://github.com/neo4j-php/neo4j-php-client
		//       https://github.com/graphaware/neo4j-php-client
		{
			ID:            "php.neo4j.session.run",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:session|sess)\s*->run\s*\(`,
			ObjectType:    "Session",
			MethodName:    "run",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Neo4j SessionInterface::run() with tainted Cypher string (Cypher injection); pass user values via the $params associative array and reference them as $name in the Cypher",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.neo4j.transaction.run",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:tx|transaction)\s*->run\s*\(`,
			ObjectType:    "Tx",
			MethodName:    "run",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Neo4j TransactionInterface::run() (inside beginTransaction/readTransaction/writeTransaction) with tainted Cypher string (Cypher injection); pass user values via the $params associative array",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.neo4j.client.run",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:client|driver|neo4jClient|neo4j_client)\s*->run\s*\(`,
			ObjectType:    "Client",
			MethodName:    "run",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Neo4j ClientInterface::run() (laudis/neo4j-php-client auto-commit) with tainted Cypher string (Cypher injection); pass user values via the $params associative array",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.neo4j.statement.create",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `\bStatement::create\s*\(`,
			ObjectType:    "Statement",
			MethodName:    "create",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Neo4j Statement::create() value-object factory with tainted Cypher text — the resulting Statement is passed to runStatement/runStatements where the embedded Cypher executes (Cypher injection); supply user values via the $params iterable, not the $text argument",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.neo4j.graphaware.sendcypherquery",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->sendCypherQuery\s*\(`,
			ObjectType:    "",
			MethodName:    "sendCypherQuery",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "graphaware/neo4j-php-client ClientInterface::sendCypherQuery() with tainted Cypher string (Cypher injection); pass user values via the $params associative array",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- DataStax PHP driver + php-cassandra (duoshuo) — CQL Injection (CWE-943) ---
		// Mirrors kotlin.cassandra.*, groovy.cassandra.*, csharp.cassandra.*,
		// rust.scylla.*, swift.cassandra.* coverage for PHP. Apache Cassandra
		// and ScyllaDB both speak CQL; concatenating tainted user input into a
		// CQL string permits CQL injection (data exfiltration, ALLOW FILTERING
		// abuse, schema disclosure). Use ? placeholder bindings instead.
		//
		// References:
		//   https://datastax.github.io/php-driver/features/simple_statements/
		//     — DataStax/php-driver (PECL `cassandra`, MAINTENANCE ONLY but
		//       still the most-used official PHP Cassandra binding)
		//   https://github.com/duoshuo/php-cassandra
		//   https://github.com/mroosz/php-cassandra (active fork)
		//     — pure-PHP driver exposing Connection->querySync/queryAsync
		{
			ID:            "php.cassandra.session.execute",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:session|sess|cassSession|cassandraSession)\s*->execute\s*\(`,
			ObjectType:    "Session",
			MethodName:    "execute",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DataStax PHP driver Cassandra\\Session::execute() with a tainted CQL string (or new Cassandra\\SimpleStatement built from one) enables CQL injection; pass user values via the 'arguments' option with ? placeholders, or use Session::prepare() + execute(prepared, ['arguments' => [...]])",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.cassandra.session.executeasync",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:session|sess|cassSession|cassandraSession)\s*->executeAsync\s*\(`,
			ObjectType:    "Session",
			MethodName:    "executeAsync",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DataStax PHP driver Cassandra\\Session::executeAsync() with a tainted CQL string (or new Cassandra\\SimpleStatement built from one) enables CQL injection; pass user values via the 'arguments' option with ? placeholders",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.cassandra.simplestatement.new",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `new\s+(?:\\?Cassandra\\)?SimpleStatement\s*\(`,
			ObjectType:    "SimpleStatement",
			MethodName:    "SimpleStatement",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DataStax PHP driver new Cassandra\\SimpleStatement($cql) with a tainted CQL text — once handed to Session::execute()/executeAsync()/prepare() the embedded CQL runs as-is (CQL injection); place ? markers in the $cql and pass values via the execute() 'arguments' option",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.cassandra.connection.querysync",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->querySync\s*\(`,
			ObjectType:    "",
			MethodName:    "querySync",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "php-cassandra (duoshuo/mroosz) Cassandra\\Connection::querySync() with a tainted CQL string enables CQL injection; pass user values via the $values argument with ? placeholders, or use prepare() + executeSync()",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.cassandra.connection.queryasync",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `->queryAsync\s*\(`,
			ObjectType:    "",
			MethodName:    "queryAsync",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "php-cassandra (duoshuo/mroosz) Cassandra\\Connection::queryAsync() with a tainted CQL string enables CQL injection; pass user values via the $values argument with ? placeholders",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// ── Cloud data warehouse SQL injection (CWE-89) ─────────────────────────
		// Google Cloud BigQuery (google/cloud-bigquery) and Cloud Spanner
		// (google/cloud-spanner) PHP client libraries, plus AWS SDK for PHP V3
		// analytics services (Athena, Redshift Data API, Timestream Query) and
		// DynamoDB PartiQL (CWE-943). All take a SQL/PartiQL string at the first
		// argument; user values must be bound via parameterized APIs
		// (BigQueryParameter[]/@params, SpannerParameterCollection, AWS SDK
		// `parameters:`/`ExecutionParameters` arrays) — string concatenation is
		// always injection-prone since none of these engines escape SQL literals.

		// --- google/cloud-bigquery: BigQueryClient::query / queryConfig ----------
		// Both methods take a SQL string at arg 0 and return a QueryJobConfiguration
		// that is then handed to runQuery()/startQuery(). The injection happens at
		// the query()/queryConfig() call where the SQL string is captured. Bind
		// user values via the 'parameters' option with @name placeholders in a
		// constant SQL template instead.
		{
			ID:            "php.bigquery.client.query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:bigQuery|bigquery|bq)\s*->query\s*\(`,
			ObjectType:    "BigQueryClient",
			MethodName:    "query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "google/cloud-bigquery BigQueryClient::query($queryString) with tainted SQL causes SQL injection; pass user values via the 'parameters' option with @name placeholders in a constant SQL template instead",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.bigquery.client.queryconfig",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:bigQuery|bigquery|bq)\s*->queryConfig\s*\(`,
			ObjectType:    "BigQueryClient",
			MethodName:    "queryConfig",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "google/cloud-bigquery BigQueryClient::queryConfig($queryString) (alias of query()) with tainted SQL causes SQL injection; bind user values via the 'parameters' option with @name placeholders in a constant SQL template instead",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- google/cloud-spanner: Database / Transaction execute / executeUpdate
		// Spanner exposes execute($sql, $opts) for SELECT and executeUpdate($sql,
		// $opts) for DML on both the Database object and inside runTransaction()
		// callbacks (Transaction object). Bind user values via $opts['parameters']
		// with @name placeholders in a constant SQL string — concatenating tainted
		// SQL is full SQL injection.
		{
			ID:            "php.spanner.database.execute",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:database|db|spanner|spannerDb|spannerDatabase)\s*->execute\s*\(`,
			ObjectType:    "Database",
			MethodName:    "execute",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "google/cloud-spanner Database::execute($sql, $opts) with tainted SQL causes SQL injection; bind user values via $opts['parameters'] with @name placeholders in a constant SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.spanner.database.executeupdate",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:database|db|spanner|spannerDb|spannerDatabase)\s*->executeUpdate\s*\(`,
			ObjectType:    "Database",
			MethodName:    "executeUpdate",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "google/cloud-spanner Database::executeUpdate($sql, $opts) with tainted SQL allows DML (UPDATE/DELETE/INSERT) injection; bind user values via $opts['parameters'] with @name placeholders in a constant DML statement",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.spanner.transaction.execute",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:transaction|tx|txn|t)\s*->execute\s*\(`,
			ObjectType:    "Transaction",
			MethodName:    "execute",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "google/cloud-spanner Transaction::execute($sql, $opts) inside runTransaction() with tainted SQL causes SQL injection; bind user values via $opts['parameters'] with @name placeholders in a constant SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.spanner.transaction.executeupdate",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:transaction|tx|txn|t)\s*->executeUpdate\s*\(`,
			ObjectType:    "Transaction",
			MethodName:    "executeUpdate",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "google/cloud-spanner Transaction::executeUpdate($sql, $opts) inside runTransaction() with tainted SQL allows DML injection; bind user values via $opts['parameters'] with @name placeholders in a constant DML statement",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- AWS SDK PHP V3: AthenaClient::startQueryExecution -------------------
		// $athena->startQueryExecution(['QueryString' => $sql, ...]). Tainted SQL
		// inside the input array reaches Athena as-is — Athena has no parameter
		// binding for general queries other than the optional ExecutionParameters
		// list (positional ? placeholders). Build queries from a fixed allowlist
		// or supply values via ExecutionParameters with ? markers.
		{
			ID:            "php.aws.athena.startqueryexecution",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:athena|athenaClient)\s*->startQueryExecution\s*\(`,
			ObjectType:    "AthenaClient",
			MethodName:    "startQueryExecution",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "AWS SDK for PHP AthenaClient::startQueryExecution(['QueryString' => $sql, ...]) with tainted SQL — Athena has no general parameter binding; use ExecutionParameters with ? placeholders or restrict to a fixed allowlist",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- AWS SDK PHP V3: RedshiftDataClient::executeStatement / batch --------
		// $redshiftData->executeStatement(['Sql' => $sql, ...]) and
		// $redshiftData->batchExecuteStatement(['Sqls' => [$sql1, ...], ...]).
		// User values must be bound via the 'Parameters' array (named markers
		// :name in the SQL); concatenating into the string is full SQL injection.
		{
			ID:            "php.aws.redshiftdata.executestatement",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:redshift|redshiftData|redshiftClient|redshiftDataClient)\s*->executeStatement\s*\(`,
			ObjectType:    "RedshiftDataClient",
			MethodName:    "executeStatement",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "AWS SDK for PHP RedshiftDataClient::executeStatement(['Sql' => $sql, ...]) with tainted SQL causes SQL injection; bind user values via the 'Parameters' array with :name placeholders in a constant SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.aws.redshiftdata.batchexecutestatement",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:redshift|redshiftData|redshiftClient|redshiftDataClient)\s*->batchExecuteStatement\s*\(`,
			ObjectType:    "RedshiftDataClient",
			MethodName:    "batchExecuteStatement",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "AWS SDK for PHP RedshiftDataClient::batchExecuteStatement(['Sqls' => [$sql, ...], ...]) with tainted SQL strings causes SQL injection; bind user values via 'Parameters' with :name placeholders in constant SQL templates",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- AWS SDK PHP V3: TimestreamQueryClient::query ------------------------
		// $timestreamQuery->query(['QueryString' => $sql, ...]). Timestream has
		// no general parameter binding — values must be quoted/escaped or
		// restricted to an allowlist.
		{
			ID:            "php.aws.timestreamquery.query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:timestream|timestreamQuery|timestreamQueryClient)\s*->query\s*\(`,
			ObjectType:    "TimestreamQueryClient",
			MethodName:    "query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "AWS SDK for PHP TimestreamQueryClient::query(['QueryString' => $sql, ...]) with tainted SQL — Timestream has no general parameter binding; restrict to a fixed allowlist or quote/escape values explicitly",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- AWS SDK PHP V3: DynamoDbClient::executeStatement (PartiQL) ---------
		// $dynamoDb->executeStatement(['Statement' => $partiqlSql, ...]). PartiQL
		// is SQL-syntactic over DynamoDB; tainted statement input enables NoSQL
		// injection (CWE-943). Bind user values via the 'Parameters' array with
		// ? placeholders in a constant PartiQL statement instead.
		{
			ID:            "php.aws.dynamodb.executestatement",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:dynamoDb|dynamodb|dynamoDbClient|ddb)\s*->executeStatement\s*\(`,
			ObjectType:    "DynamoDbClient",
			MethodName:    "executeStatement",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "AWS SDK for PHP DynamoDbClient::executeStatement(['Statement' => $partiqlSql, ...]) with tainted PartiQL string enables NoSQL/PartiQL injection; bind user values via the 'Parameters' array with ? placeholders in a constant PartiQL statement",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Native PostgreSQL (pgsql ext) first-order SQLi (CWE-89) ---
		// pg_query($conn, $sql) / pg_query($sql) and the async pg_send_query()
		// execute the SQL string verbatim. Building the query from user input
		// is first-order SQLi. The safe API is pg_query_params() /
		// pg_send_query_params() / pg_prepare()+pg_execute() (registered as
		// sanitizers) which bind values via $1, $2 placeholders. The SQL is the
		// last argument, so both the one-arg and two-arg forms are flagged.
		{
			ID:            "php.pg_query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\bpg_query\s*\(`,
			ObjectType:    "",
			MethodName:    "pg_query",
			DangerousArgs: []int{0, 1},
			Severity:      rules.Critical,
			Description:   "SQL injection via pg_query() — executes the query string verbatim; use pg_query_params() with $1/$2 placeholders instead",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.pg_send_query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\bpg_send_query\s*\(`,
			ObjectType:    "",
			MethodName:    "pg_send_query",
			DangerousArgs: []int{0, 1},
			Severity:      rules.Critical,
			Description:   "SQL injection via pg_send_query() (async) — sends the query string verbatim; use pg_send_query_params() with $1/$2 placeholders instead",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Symfony Process — OS command execution (CWE-78) ---
		// new Process([...]) followed by ->run()/->mustRun() executes the
		// supplied argv; Process::fromShellCommandline('cmd '.$input) parses the
		// string through /bin/sh, so any tainted text becomes shell injection.
		// The array constructor still allows binary/argument injection when the
		// elements are user-controlled. ->run()/->mustRun() trigger execution.
		{
			ID:            "php.symfony.process.new",
			Category:      taint.SnkCommand,
			Language:      rules.LangPHP,
			Pattern:       `new\s+\\?(?:Symfony\\Component\\Process\\)?Process\s*\(`,
			ObjectType:    "Symfony\\Component\\Process\\Process",
			MethodName:    "Process",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Symfony Process constructed with tainted argv/command — executes on ->run()/->mustRun(); pass fixed argv elements and never interpolate user input",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.symfony.process.fromshellcommandline",
			Category:      taint.SnkCommand,
			Language:      rules.LangPHP,
			Pattern:       `Process::fromShellCommandline\s*\(`,
			ObjectType:    "Symfony\\Component\\Process\\Process",
			MethodName:    "fromShellCommandline",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Symfony Process::fromShellCommandline() parses the command through /bin/sh — tainted input is shell command injection; use the array-argv Process constructor instead",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- SQLite3 class — first-order SQLi (CWE-89) ---
		// SQLite3::query()/querySingle()/exec() run the SQL string verbatim.
		// Scoped to a $db/$sqlite/$conn receiver so the generic ->query/->exec
		// PDO sinks aren't duplicated. The safe API is SQLite3::prepare()
		// (parameterized, already covered by the generic prepare sanitizer) and
		// SQLite3::escapeString() (registered as a sanitizer).
		{
			ID:            "php.sqlite3.query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:db|sqlite|sqlite3|conn)\w*\s*->query\s*\(`,
			ObjectType:    "SQLite3",
			MethodName:    "query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL injection via SQLite3::query() with a tainted SQL string; use SQLite3::prepare() with bound parameters instead",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.sqlite3.querysingle",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:db|sqlite|sqlite3|conn)\w*\s*->querySingle\s*\(`,
			ObjectType:    "SQLite3",
			MethodName:    "querySingle",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL injection via SQLite3::querySingle() with a tainted SQL string; use SQLite3::prepare() with bound parameters instead",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.sqlite3.exec",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\$(?:db|sqlite|sqlite3|conn)\w*\s*->exec\s*\(`,
			ObjectType:    "SQLite3",
			MethodName:    "exec",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL injection via SQLite3::exec() with a tainted SQL string; use SQLite3::prepare() with bound parameters instead",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Microsoft SQL Server (sqlsrv ext) — SQLi (CWE-89) ---
		// sqlsrv_query($conn, $sql) and sqlsrv_prepare($conn, $sql) run/prepare
		// the raw query string. The safe form passes a $params array with ?
		// placeholders in a constant statement — which the regex engine can't
		// reliably distinguish, so no MSSQL-specific sanitizer is registered.
		{
			ID:            "php.sqlsrv_query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\bsqlsrv_query\s*\(`,
			ObjectType:    "",
			MethodName:    "sqlsrv_query",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "SQL injection via sqlsrv_query() — runs the query string verbatim; pass user values through the $params array with ? placeholders in a constant statement",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.sqlsrv_prepare",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\bsqlsrv_prepare\s*\(`,
			ObjectType:    "",
			MethodName:    "sqlsrv_prepare",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "SQL injection via sqlsrv_prepare() — prepares the query string verbatim; keep the statement constant and bind user values through the $params array with ? placeholders",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Oracle OCI8 — SQL injection (CWE-89) ---
		// oci_parse($connection, $sql) prepares the SQL/PL-SQL text (arg 1)
		// verbatim; the string is fixed at parse time and later run by
		// oci_execute(). A tainted statement is classic Oracle SQLi — bind
		// user values with oci_bind_by_name() and :placeholders instead.
		{
			ID:            "php.oci_parse",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\boci_parse\s*\(`,
			ObjectType:    "",
			MethodName:    "oci_parse",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "SQL injection via oci_parse() — prepares the Oracle SQL/PL-SQL string verbatim; bind user values with oci_bind_by_name() and :placeholders in a constant statement",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- ODBC — SQL injection (CWE-89) ---
		// odbc_exec($conn, $query) runs the query (arg 1) immediately and
		// odbc_prepare($conn, $query) prepares it; both take the SQL string
		// verbatim. Use odbc_prepare() with ? placeholders + odbc_execute()
		// $params instead of interpolating user input.
		{
			ID:            "php.odbc_exec",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\bodbc_exec\s*\(`,
			ObjectType:    "",
			MethodName:    "odbc_exec",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "SQL injection via odbc_exec() — sends the query string verbatim to the ODBC driver; use odbc_prepare() with ? placeholders and bind values through odbc_execute()",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.odbc_prepare",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\bodbc_prepare\s*\(`,
			ObjectType:    "",
			MethodName:    "odbc_prepare",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "SQL injection via odbc_prepare() — prepares the query string verbatim; keep the statement constant with ? placeholders and bind user values through odbc_execute()",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- IBM DB2 (ibm_db2) — SQL injection (CWE-89) ---
		// db2_exec($conn, $stmt) runs the statement (arg 1) and
		// db2_prepare($conn, $stmt) prepares it; both execute the SQL text
		// verbatim. Use db2_prepare() with ? placeholders + db2_bind_param()
		// / db2_execute() instead of concatenating user input.
		{
			ID:            "php.db2_exec",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\bdb2_exec\s*\(`,
			ObjectType:    "",
			MethodName:    "db2_exec",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "SQL injection via db2_exec() — runs the statement string verbatim on DB2; use db2_prepare() with ? placeholders and bind user values via db2_bind_param()/db2_execute()",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.db2_prepare",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPHP,
			Pattern:       `\bdb2_prepare\s*\(`,
			ObjectType:    "",
			MethodName:    "db2_prepare",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "SQL injection via db2_prepare() — prepares the statement string verbatim on DB2; keep the statement constant with ? placeholders and bind user values via db2_bind_param()/db2_execute()",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Symfony HttpClient — SSRF (CWE-918) ---
		// HttpClientInterface::request($method, $url, $options) fetches the URL.
		// A tainted $url (arg 1) lets an attacker pivot to internal endpoints.
		// Scoped to a *client receiver ($httpClient->request / $this->client->
		// request) so unrelated ->request() methods don't false-positive.
		{
			ID:            "php.symfony.httpclient.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPHP,
			Pattern:       `(?:\$\w*[Cc]lient|->\w*[Cc]lient)\s*->request\s*\(`,
			ObjectType:    "Symfony\\Contracts\\HttpClient\\HttpClientInterface",
			MethodName:    "request",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "SSRF via Symfony HttpClientInterface::request($method, $url) with a tainted URL; validate the host against an allowlist before fetching",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- ReDoS — regex compiled/matched on an untrusted PATTERN (CWE-1333) ---
		// preg_match($pattern, ...) / preg_match_all / preg_replace where the
		// PATTERN argument is a variable (user-controlled) lets an attacker
		// supply a catastrophically-backtracking regex (or a /e-style payload).
		// Scoped to `\(\s*\$` so a literal-string pattern (the overwhelmingly
		// common, safe form) does NOT match. preg_quote() neutralizes this.
		{
			ID:            "php.preg_match.dynamic_pattern",
			Category:      taint.SnkRegexDoS,
			Language:      rules.LangPHP,
			Pattern:       `\bpreg_match(?:_all)?\s*\(\s*\$`,
			ObjectType:    "",
			MethodName:    "preg_match/preg_match_all",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ReDoS via preg_match()/preg_match_all() with a user-controlled regex PATTERN — an attacker can supply a catastrophically-backtracking expression; use a fixed pattern or preg_quote() the dynamic portion",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.preg_replace.dynamic_pattern",
			Category:      taint.SnkRegexDoS,
			Language:      rules.LangPHP,
			Pattern:       `\bpreg_replace(?:_callback)?\s*\(\s*\$`,
			ObjectType:    "",
			MethodName:    "preg_replace/preg_replace_callback",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ReDoS via preg_replace()/preg_replace_callback() with a user-controlled regex PATTERN — an attacker can supply a catastrophically-backtracking expression; use a fixed pattern or preg_quote() the dynamic portion",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},
		// preg_split($pattern, ...) / preg_grep($pattern, ...) round out the
		// PCRE family: both take the regex PATTERN as their FIRST argument, so
		// a user-controlled pattern is the same ReDoS hazard as preg_match /
		// preg_replace. Scoped to `\(\s*\$` so the common literal-pattern form
		// (preg_split('/,/', $csv)) stays silent. preg_quote() neutralizes it.
		{
			ID:            "php.preg_split.dynamic_pattern",
			Category:      taint.SnkRegexDoS,
			Language:      rules.LangPHP,
			Pattern:       `\bpreg_split\s*\(\s*\$`,
			ObjectType:    "",
			MethodName:    "preg_split",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ReDoS via preg_split() with a user-controlled regex PATTERN (arg 0) — an attacker can supply a catastrophically-backtracking expression; use a fixed delimiter pattern or preg_quote() the dynamic portion",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.preg_grep.dynamic_pattern",
			Category:      taint.SnkRegexDoS,
			Language:      rules.LangPHP,
			Pattern:       `\bpreg_grep\s*\(\s*\$`,
			ObjectType:    "",
			MethodName:    "preg_grep",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ReDoS via preg_grep() with a user-controlled regex PATTERN (arg 0) — an attacker can supply a catastrophically-backtracking expression; use a fixed pattern or preg_quote() the dynamic portion",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},
		// mbstring multibyte regex (mb_ereg*) is backed by Oniguruma, which —
		// unlike PCRE — has NO pcre.backtrack_limit safety net, so a tainted
		// pattern is an even stronger ReDoS vector. All of mb_ereg / mb_eregi /
		// mb_ereg_match take the PATTERN as arg 0. There is no built-in
		// mb_ereg_quote(), so the only safe form is a fixed pattern.
		{
			ID:            "php.mb_ereg.dynamic_pattern",
			Category:      taint.SnkRegexDoS,
			Language:      rules.LangPHP,
			Pattern:       `\bmb_ereg(?:i|_match)?\s*\(\s*\$`,
			ObjectType:    "",
			MethodName:    "mb_ereg/mb_eregi/mb_ereg_match",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ReDoS via mb_ereg()/mb_eregi()/mb_ereg_match() with a user-controlled regex PATTERN (arg 0) — Oniguruma has no backtrack limit, so a crafted pattern causes catastrophic backtracking; use a fixed pattern",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.mb_ereg_replace.dynamic_pattern",
			Category:      taint.SnkRegexDoS,
			Language:      rules.LangPHP,
			Pattern:       `\bmb_eregi?_replace(?:_callback)?\s*\(\s*\$`,
			ObjectType:    "",
			MethodName:    "mb_ereg_replace/mb_eregi_replace/mb_ereg_replace_callback",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ReDoS via mb_ereg_replace()/mb_eregi_replace()/mb_ereg_replace_callback() with a user-controlled regex PATTERN (arg 0) — Oniguruma has no backtrack limit; use a fixed pattern",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Mass assignment (CWE-915) — Laravel Eloquent ---
		// fill()/forceFill() bind an associative array of attributes onto a
		// model. When the array is request-controlled (e.g. $request->all()),
		// an attacker can set columns the developer never intended (is_admin,
		// role, account_id). forceFill() is strictly worse: it bypasses the
		// $fillable/$guarded allow-list entirely. The dangerous arg is the
		// attribute array (arg index 0). These method names are
		// Eloquent-specific, so the pattern stays narrow; the taint engine
		// only fires when the array argument actually carries request taint.
		{
			ID:            "php.laravel.mass_assign.fill",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPHP,
			Pattern:       `->fill\s*\(`,
			ObjectType:    "Eloquent",
			MethodName:    "fill",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Laravel Eloquent mass assignment via ->fill() with a request-controlled attribute array — an attacker can set columns outside the intended set; pass an explicitly whitelisted array (e.g. $request->only([...])) instead of $request->all()",
			CWEID:         "CWE-915",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "php.laravel.mass_assign.forcefill",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPHP,
			Pattern:       `->forceFill\s*\(`,
			ObjectType:    "Eloquent",
			MethodName:    "forceFill",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Laravel Eloquent mass assignment via ->forceFill() with a request-controlled attribute array — forceFill() bypasses the $fillable/$guarded allow-list entirely, letting an attacker set any column; never feed it user input",
			CWEID:         "CWE-915",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- Format string injection (CWE-134) ---
		// sprintf/vsprintf/vprintf interpret arg 0 as a format string. When
		// that format specifier is request-controlled the attacker can inject
		// conversion directives (%n is unavailable in PHP, but %1$… argument
		// swapping, width/precision DoS, and %s on unintended args leak/abuse
		// data). The dangerous arg is the format string (arg index 0). Note:
		// this is distinct from php.printf (CWE-79, unescaped *output*) — here
		// the FORMAT itself is tainted.
		{
			ID:            "php.format.sprintf",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `\bv?sprintf\s*\(`,
			ObjectType:    "",
			MethodName:    "sprintf/vsprintf",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Format string injection via sprintf()/vsprintf() with a tainted format specifier (arg 0) — an attacker can inject conversion directives; pass user data only as format ARGUMENTS, keep the format string a literal",
			CWEID:         "CWE-134",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "php.format.vprintf",
			Category:      taint.SnkEval,
			Language:      rules.LangPHP,
			Pattern:       `\bvprintf\s*\(`,
			ObjectType:    "",
			MethodName:    "vprintf",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Format string injection via vprintf() with a tainted format specifier (arg 0) — keep the format string a literal and pass user data only via the arguments array",
			CWEID:         "CWE-134",
			OWASPCategory: "A03:2021-Injection",
		},
	}
}
