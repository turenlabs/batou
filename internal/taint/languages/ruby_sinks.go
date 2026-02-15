package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

func (rubyCatalog) Sinks() []taint.SinkDef {
	return []taint.SinkDef{
		// SQL injection
		{ID: "ruby.activerecord.execute", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.execute\s*\(`, ObjectType: "ActiveRecord", MethodName: "execute", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL execution via ActiveRecord", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.activerecord.exec_query", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.exec_query\s*\(`, ObjectType: "ActiveRecord", MethodName: "exec_query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL exec_query via ActiveRecord", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.activerecord.connection.execute", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `ActiveRecord::Base\.connection\.execute\s*\(`, ObjectType: "ActiveRecord::Base", MethodName: "execute", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Direct SQL execution via ActiveRecord connection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.activerecord.where.interpolation", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.where\s*\(\s*["'].*#\{`, ObjectType: "ActiveRecord", MethodName: "where", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via string interpolation in .where()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.activerecord.order.interpolation", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.order\s*\(\s*["'].*#\{`, ObjectType: "ActiveRecord", MethodName: "order", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via string interpolation in .order()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// Command injection
		{ID: "ruby.system", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `\bsystem\s*\(`, ObjectType: "", MethodName: "system", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via system()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.exec", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `\bexec\s*\(`, ObjectType: "", MethodName: "exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via exec()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.backticks", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: "`.+`", ObjectType: "", MethodName: "backticks", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via backticks", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.percent_x", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `%x\(`, ObjectType: "", MethodName: "%x()", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via %x()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.open3.capture2", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `Open3\.capture2\s*\(`, ObjectType: "Open3", MethodName: "capture2", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command via Open3.capture2", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.io.popen", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `IO\.popen\s*\(`, ObjectType: "IO", MethodName: "popen", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command via IO.popen", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

		// Code evaluation
		{ID: "ruby.eval", Category: taint.SnkEval, Language: rules.LangRuby, Pattern: `\beval\s*\(`, ObjectType: "", MethodName: "eval", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Dynamic code evaluation via eval()", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.send", Category: taint.SnkEval, Language: rules.LangRuby, Pattern: `\.send\s*\(`, ObjectType: "", MethodName: "send", DangerousArgs: []int{0}, Severity: rules.High, Description: "Dynamic method invocation via send()", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.public_send", Category: taint.SnkEval, Language: rules.LangRuby, Pattern: `\.public_send\s*\(`, ObjectType: "", MethodName: "public_send", DangerousArgs: []int{0}, Severity: rules.High, Description: "Dynamic method invocation via public_send()", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

		// XSS
		{ID: "ruby.rails.render.html", Category: taint.SnkHTMLOutput, Language: rules.LangRuby, Pattern: `render\s+html\s*:`, ObjectType: "ActionController", MethodName: "render html:", DangerousArgs: []int{0}, Severity: rules.High, Description: "Rails render html (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.rails.render.inline", Category: taint.SnkHTMLOutput, Language: rules.LangRuby, Pattern: `render\s+inline\s*:`, ObjectType: "ActionController", MethodName: "render inline:", DangerousArgs: []int{0}, Severity: rules.High, Description: "Rails render inline (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

		// File serving via render
		{ID: "ruby.rails.render.file", Category: taint.SnkFileWrite, Language: rules.LangRuby, Pattern: `render\s+file\s*:`, ObjectType: "ActionController", MethodName: "render file:", DangerousArgs: []int{0}, Severity: rules.High, Description: "Rails render file: with tainted path (arbitrary file read)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// Redirect
		{ID: "ruby.rails.redirect_to", Category: taint.SnkRedirect, Language: rules.LangRuby, Pattern: `redirect_to\s*\(`, ObjectType: "ActionController", MethodName: "redirect_to", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via redirect_to", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},

		// File operations
		{ID: "ruby.file.open", Category: taint.SnkFileWrite, Language: rules.LangRuby, Pattern: `File\.open\s*\(`, ObjectType: "File", MethodName: "open", DangerousArgs: []int{0}, Severity: rules.High, Description: "File open with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "ruby.file.write", Category: taint.SnkFileWrite, Language: rules.LangRuby, Pattern: `File\.write\s*\(`, ObjectType: "File", MethodName: "write", DangerousArgs: []int{0}, Severity: rules.High, Description: "File write with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "ruby.fileutils", Category: taint.SnkFileWrite, Language: rules.LangRuby, Pattern: `FileUtils\.`, ObjectType: "FileUtils", MethodName: "FileUtils", DangerousArgs: []int{-1}, Severity: rules.High, Description: "FileUtils operation with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// Deserialization
		{ID: "ruby.marshal.load", Category: taint.SnkDeserialize, Language: rules.LangRuby, Pattern: `Marshal\.load\s*\(`, ObjectType: "Marshal", MethodName: "load", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Unsafe deserialization via Marshal.load", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
		{ID: "ruby.yaml.load", Category: taint.SnkDeserialize, Language: rules.LangRuby, Pattern: `YAML\.load\s*\(`, ObjectType: "YAML", MethodName: "load", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Unsafe YAML deserialization", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

		// SSRF
		{ID: "ruby.net.http.get", Category: taint.SnkURLFetch, Language: rules.LangRuby, Pattern: `Net::HTTP\.get\s*\(`, ObjectType: "Net::HTTP", MethodName: "get", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via Net::HTTP.get", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "ruby.httparty.get", Category: taint.SnkURLFetch, Language: rules.LangRuby, Pattern: `HTTParty\.get\s*\(`, ObjectType: "HTTParty", MethodName: "get", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via HTTParty.get", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "ruby.faraday.get", Category: taint.SnkURLFetch, Language: rules.LangRuby, Pattern: `Faraday\.get\s*\(`, ObjectType: "Faraday", MethodName: "get", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via Faraday.get", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

		// Template injection
		{ID: "ruby.erb.new", Category: taint.SnkTemplate, Language: rules.LangRuby, Pattern: `ERB\.new\s*\(`, ObjectType: "ERB", MethodName: "new", DangerousArgs: []int{0}, Severity: rules.High, Description: "ERB template injection", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},

		// Sequel SQL injection
		{ID: "ruby.sequel.db.run", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `DB\.run\s*\(`, ObjectType: "Sequel::Database", MethodName: "run", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Raw SQL execution via Sequel DB.run", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.sequel.db.fetch", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `DB\.fetch\s*\(`, ObjectType: "Sequel::Database", MethodName: "fetch", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Raw SQL execution via Sequel DB.fetch", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.sequel.where.interpolation", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.where\s*\(\s*["'].*#\{`, ObjectType: "Sequel::Dataset", MethodName: "where", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via string interpolation in Sequel .where()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.sequel.db.execute", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `DB\.execute\s*\(`, ObjectType: "Sequel::Database", MethodName: "execute", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Raw SQL execution via Sequel DB.execute", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// Arel raw SQL
		{ID: "ruby.arel.sql", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `Arel\.sql\s*\(`, ObjectType: "Arel", MethodName: "sql", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Raw SQL string via Arel.sql() with tainted input", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// ERB raw output (XSS)
		{ID: "ruby.erb.raw_output", Category: taint.SnkHTMLOutput, Language: rules.LangRuby, Pattern: `<%==\s*`, ObjectType: "ERB", MethodName: "<%== %>", DangerousArgs: []int{0}, Severity: rules.High, Description: "ERB raw unescaped output (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.rails.raw", Category: taint.SnkHTMLOutput, Language: rules.LangRuby, Pattern: `\braw\s*\(`, ObjectType: "ActionView", MethodName: "raw", DangerousArgs: []int{0}, Severity: rules.High, Description: "Rails raw() bypasses HTML escaping (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.rails.html_safe", Category: taint.SnkHTMLOutput, Language: rules.LangRuby, Pattern: `\.html_safe`, ObjectType: "String", MethodName: "html_safe", DangerousArgs: []int{0}, Severity: rules.High, Description: "Marking tainted string as html_safe (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

		// ActionMailer header injection
		{ID: "ruby.actionmailer.header_injection", Category: taint.SnkHeader, Language: rules.LangRuby, Pattern: `mail\s*\(\s*to\s*:.*#\{`, ObjectType: "ActionMailer", MethodName: "mail", DangerousArgs: []int{0}, Severity: rules.High, Description: "Email header injection via ActionMailer mail()", CWEID: "CWE-93", OWASPCategory: "A03:2021-Injection"},

		// Nokogiri XXE
		{ID: "ruby.nokogiri.xml.parse", Category: taint.SnkDeserialize, Language: rules.LangRuby, Pattern: `Nokogiri::XML\s*\(`, ObjectType: "Nokogiri::XML", MethodName: "XML", DangerousArgs: []int{0}, Severity: rules.High, Description: "XML parsing with potential XXE via Nokogiri", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
		{ID: "ruby.nokogiri.html.parse", Category: taint.SnkDeserialize, Language: rules.LangRuby, Pattern: `Nokogiri::HTML\s*\(`, ObjectType: "Nokogiri::HTML", MethodName: "HTML", DangerousArgs: []int{0}, Severity: rules.High, Description: "HTML parsing of untrusted input via Nokogiri", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},

		// OpenURI SSRF
		{ID: "ruby.open_uri.open", Category: taint.SnkURLFetch, Language: rules.LangRuby, Pattern: `\bopen\s*\(\s*["']https?://`, ObjectType: "OpenURI", MethodName: "open", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via OpenURI open() with tainted URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "ruby.uri.open", Category: taint.SnkURLFetch, Language: rules.LangRuby, Pattern: `URI\.open\s*\(`, ObjectType: "URI", MethodName: "open", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via URI.open() with tainted URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

		// Kernel.open pipe injection
		{ID: "ruby.kernel.open", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `\bKernel\.open\s*\(`, ObjectType: "Kernel", MethodName: "open", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Command injection via Kernel.open() pipe character", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.open.pipe", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `\bopen\s*\(\s*["']\|`, ObjectType: "Kernel", MethodName: "open", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Command injection via open() with pipe prefix", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

		// Tempfile tainted names
		{ID: "ruby.tempfile.new", Category: taint.SnkFileWrite, Language: rules.LangRuby, Pattern: `Tempfile\.new\s*\(`, ObjectType: "Tempfile", MethodName: "new", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Tempfile creation with tainted name (path traversal)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// ActiveStorage filename injection
		{ID: "ruby.activestorage.filename", Category: taint.SnkFileWrite, Language: rules.LangRuby, Pattern: `\.attach\s*\(\s*.*filename\s*:`, ObjectType: "ActiveStorage", MethodName: "attach", DangerousArgs: []int{0}, Severity: rules.High, Description: "ActiveStorage attachment with tainted filename", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// Weak cryptographic hash (CWE-328)
		{ID: "ruby.crypto.digest.md5", Category: taint.SnkCrypto, Language: rules.LangRuby, Pattern: `Digest::MD5\.\w+\s*\(`, ObjectType: "Digest::MD5", MethodName: "MD5", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Weak MD5 hash algorithm usage", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "ruby.crypto.digest.sha1", Category: taint.SnkCrypto, Language: rules.LangRuby, Pattern: `Digest::SHA1\.\w+\s*\(`, ObjectType: "Digest::SHA1", MethodName: "SHA1", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Weak SHA1 hash algorithm usage", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},

		// Weak encryption (CWE-327)
		{ID: "ruby.crypto.openssl.weak_cipher", Category: taint.SnkCrypto, Language: rules.LangRuby, Pattern: `OpenSSL::Cipher\.new\s*\(\s*['"](?:DES|RC4|des|rc4)`, ObjectType: "OpenSSL::Cipher", MethodName: "Cipher.new(DES/RC4)", DangerousArgs: []int{0}, Severity: rules.High, Description: "Weak cipher algorithm (DES/RC4, use AES-GCM instead)", CWEID: "CWE-327", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "ruby.crypto.openssl.ecb_mode", Category: taint.SnkCrypto, Language: rules.LangRuby, Pattern: `OpenSSL::Cipher\.new\s*\(\s*['"].*ECB`, ObjectType: "OpenSSL::Cipher", MethodName: "Cipher.new(ECB)", DangerousArgs: []int{0}, Severity: rules.High, Description: "ECB mode cipher usage (no diffusion, use CBC/GCM)", CWEID: "CWE-327", OWASPCategory: "A02:2021-Cryptographic Failures"},

		// Insecure random (CWE-338)
		{ID: "ruby.crypto.insecure_rand", Category: taint.SnkCrypto, Language: rules.LangRuby, Pattern: `\brand\s*\(|\bsrand\s*\(`, ObjectType: "Kernel", MethodName: "rand", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Non-cryptographic random for security (use SecureRandom instead)", CWEID: "CWE-338", OWASPCategory: "A02:2021-Cryptographic Failures"},

		// Redis command injection
		{ID: "ruby.redis.call", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `redis\.call\s*\(|\.call\s*\(\s*['"]`, ObjectType: "Redis", MethodName: "call", DangerousArgs: []int{0}, Severity: rules.High, Description: "Redis command execution with tainted arguments", CWEID: "CWE-77", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.redis.eval", Category: taint.SnkEval, Language: rules.LangRuby, Pattern: `redis\.eval\s*\(`, ObjectType: "Redis", MethodName: "eval", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Redis Lua script evaluation with tainted script", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

		// DNS lookup with tainted hostname
		{ID: "ruby.resolv.getaddress", Category: taint.SnkURLFetch, Language: rules.LangRuby, Pattern: `Resolv\.getaddress\s*\(|Resolv\.getaddresses\s*\(`, ObjectType: "Resolv", MethodName: "getaddress", DangerousArgs: []int{0}, Severity: rules.High, Description: "DNS lookup with tainted hostname (SSRF/DNS rebinding)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

		// SMTP header injection
		{ID: "ruby.net.smtp.sendmail", Category: taint.SnkHeader, Language: rules.LangRuby, Pattern: `Net::SMTP.*\.send_message\s*\(|\.send_message\s*\(`, ObjectType: "Net::SMTP", MethodName: "send_message", DangerousArgs: []int{1, 2}, Severity: rules.High, Description: "SMTP send with tainted headers/recipients (email injection)", CWEID: "CWE-93", OWASPCategory: "A03:2021-Injection"},

		// Docker exec
		{ID: "ruby.docker.exec", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `container\.exec\s*\(|Docker::Container.*\.exec\s*\(`, ObjectType: "Docker::Container", MethodName: "exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Docker container exec with tainted command", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

		// Bunny/AMQP message construction
		{ID: "ruby.bunny.publish", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `\.publish\s*\(|exchange\.publish\s*\(`, ObjectType: "Bunny::Exchange", MethodName: "publish", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "AMQP message published with tainted data via Bunny", CWEID: "CWE-77", OWASPCategory: "A03:2021-Injection"},

		// Log injection (CWE-117)
		{ID: "ruby.logger.info", Category: taint.SnkLog, Language: rules.LangRuby, Pattern: `logger\.info\s*[\(\s]`, ObjectType: "Logger", MethodName: "info", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Logger info with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "ruby.logger.warn", Category: taint.SnkLog, Language: rules.LangRuby, Pattern: `logger\.warn\s*[\(\s]`, ObjectType: "Logger", MethodName: "warn", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Logger warn with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "ruby.logger.error", Category: taint.SnkLog, Language: rules.LangRuby, Pattern: `logger\.error\s*[\(\s]`, ObjectType: "Logger", MethodName: "error", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Logger error with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "ruby.logger.debug", Category: taint.SnkLog, Language: rules.LangRuby, Pattern: `logger\.debug\s*[\(\s]`, ObjectType: "Logger", MethodName: "debug", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Logger debug with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "ruby.logger.fatal", Category: taint.SnkLog, Language: rules.LangRuby, Pattern: `logger\.fatal\s*[\(\s]`, ObjectType: "Logger", MethodName: "fatal", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Logger fatal with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "ruby.rails.logger.info", Category: taint.SnkLog, Language: rules.LangRuby, Pattern: `Rails\.logger\.info\s*[\(\s]`, ObjectType: "Rails.logger", MethodName: "info", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Rails.logger.info with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "ruby.rails.logger.warn", Category: taint.SnkLog, Language: rules.LangRuby, Pattern: `Rails\.logger\.warn\s*[\(\s]`, ObjectType: "Rails.logger", MethodName: "warn", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Rails.logger.warn with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "ruby.rails.logger.error", Category: taint.SnkLog, Language: rules.LangRuby, Pattern: `Rails\.logger\.error\s*[\(\s]`, ObjectType: "Rails.logger", MethodName: "error", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Rails.logger.error with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "ruby.rails.logger.debug", Category: taint.SnkLog, Language: rules.LangRuby, Pattern: `Rails\.logger\.debug\s*[\(\s]`, ObjectType: "Rails.logger", MethodName: "debug", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Rails.logger.debug with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},

		// LDAP injection
		{ID: "ruby.net_ldap.search", Category: taint.SnkLDAP, Language: rules.LangRuby, Pattern: `(?:ldap|LDAP)\.search\s*\(`, ObjectType: "Net::LDAP", MethodName: "search", DangerousArgs: []int{0}, Severity: rules.High, Description: "LDAP search with tainted filter via net-ldap", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.net_ldap.filter.eq", Category: taint.SnkLDAP, Language: rules.LangRuby, Pattern: `Net::LDAP::Filter\.eq\s*\(`, ObjectType: "Net::LDAP::Filter", MethodName: "eq", DangerousArgs: []int{0}, Severity: rules.High, Description: "LDAP filter construction with tainted values", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},

		// XPath injection
		{ID: "ruby.nokogiri.xpath", Category: taint.SnkXPath, Language: rules.LangRuby, Pattern: `\.xpath\s*\(|\.css\s*\(`, ObjectType: "Nokogiri::XML::Node", MethodName: "xpath/css", DangerousArgs: []int{0}, Severity: rules.High, Description: "Nokogiri XPath/CSS query with tainted expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.rexml.xpath", Category: taint.SnkXPath, Language: rules.LangRuby, Pattern: `REXML::XPath\.(?:first|each|match)\s*\(`, ObjectType: "REXML::XPath", MethodName: "first/each/match", DangerousArgs: []int{0}, Severity: rules.High, Description: "REXML XPath query with tainted expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},

		// Additional template injection
		{ID: "ruby.liquid.template.parse", Category: taint.SnkTemplate, Language: rules.LangRuby, Pattern: `Liquid::Template\.parse\s*\(`, ObjectType: "Liquid::Template", MethodName: "parse", DangerousArgs: []int{0}, Severity: rules.High, Description: "Liquid template parsing with tainted template", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.haml.engine.new", Category: taint.SnkTemplate, Language: rules.LangRuby, Pattern: `Haml::Engine\.new\s*\(`, ObjectType: "Haml::Engine", MethodName: "new", DangerousArgs: []int{0}, Severity: rules.High, Description: "Haml template rendering with tainted template", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.slim.template.new", Category: taint.SnkTemplate, Language: rules.LangRuby, Pattern: `Slim::Template\.new\s*\(`, ObjectType: "Slim::Template", MethodName: "new", DangerousArgs: []int{0}, Severity: rules.High, Description: "Slim template rendering with tainted template", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},

		// HTTP response header injection
		{ID: "ruby.rails.response.headers", Category: taint.SnkHeader, Language: rules.LangRuby, Pattern: `response\.headers\s*\[|response\.set_header\s*\(`, ObjectType: "ActionDispatch::Response", MethodName: "headers[]/set_header", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "HTTP response header injection via Rails response", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.sinatra.headers", Category: taint.SnkHeader, Language: rules.LangRuby, Pattern: `headers\s*\[|header\s*\(`, ObjectType: "Sinatra::Base", MethodName: "headers[]/header", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "HTTP response header injection via Sinatra", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},

		// Dynamic class instantiation
		{ID: "ruby.constantize", Category: taint.SnkEval, Language: rules.LangRuby, Pattern: `\.constantize`, ObjectType: "String", MethodName: "constantize", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Dynamic class instantiation via constantize (RCE)", CWEID: "CWE-470", OWASPCategory: "A03:2021-Injection"},
	}
}
