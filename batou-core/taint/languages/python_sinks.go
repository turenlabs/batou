package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (c *PythonCatalog) Sinks() []taint.SinkDef {
	return []taint.SinkDef{
		// --- SQL Injection (CWE-89) ---
		// Receiver-scoping note (PR-CAT2py): the bare `\.execute\(` regex
		// fires on Redis `pipeline.execute()`, dramatiq actor `.execute()`,
		// asyncio Future `.execute()`, and many SDK fluent APIs that have
		// nothing to do with SQL. Tsflow's matcher already required the
		// receiver to look like a `cursor`/`cur`/`db` via the catalog
		// ObjectType="cursor" heuristic, but the cross-file regex walker
		// (scanPythonBodyForSinks) only ever consults the Pattern field.
		// Anchor the Pattern to common DB-client receiver names so the
		// interprocedural walker also rejects unrelated `.execute()` calls.
		// True positives use these names (cursor/cur/conn/connection/db/
		// session/engine/c) and Python's PEP-249 nudges code in that
		// direction. Same SQL-execute coverage is also enforced by the
		// peer entries below (py.sqlalchemy.engine.execute,
		// py.django.cursor.execute, py.asyncpg.execute, etc.).
		{
			ID:            "py.cursor.execute",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\b(?:cursor|cur|conn|connection|db|session|engine|c)\.execute\(`,
			ObjectType:    "cursor",
			MethodName:    "execute",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL query execution with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Command Injection (CWE-78) ---
		{
			ID:            "py.os.system",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `os\.system\(`,
			ObjectType:    "",
			MethodName:    "os.system",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "OS command execution with potentially tainted input",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.os.popen",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `os\.popen\(`,
			ObjectType:    "",
			MethodName:    "os.popen",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "OS command via popen with potentially tainted input",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.subprocess.call",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `subprocess\.\w+\(`,
			ObjectType:    "",
			MethodName:    "subprocess.run/subprocess.call/subprocess.check_output/subprocess.check_call",
			Module:        "subprocess",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Subprocess execution with potentially tainted input",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Code Injection (CWE-94) ---
		{
			ID:            "py.eval",
			Category:      taint.SnkEval,
			Language:      rules.LangPython,
			Pattern:       `(?:^|[^A-Za-z0-9_])eval\(`,
			ObjectType:    "",
			MethodName:    "eval",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Dynamic code evaluation with potentially tainted input",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:       "py.exec",
			Category: taint.SnkEval,
			Language: rules.LangPython,
			// Boundary prefix (regex/cross-file path) drops identifier-substring
			// hits like `myexec(`/`reexec(`; @global (AST/tsflow path) drops
			// method-style `session.exec(stmt)` (SQLModel/SQLAlchemy execution),
			// `connection.exec(sql)`, `subprocess_handle.exec(cmd_array)`,
			// `ssh.exec(remote_cmd)`, etc. — these are NOT Python's builtin
			// `exec()`. SQLModel's `session.exec()` produced the dominant FP
			// shape (CWE-94 Critical) on tiangolo/full-stack-fastapi-template.
			Pattern:       `(?:^|[^A-Za-z0-9_])exec\(`,
			ObjectType:    "@global",
			MethodName:    "exec",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Dynamic code execution with potentially tainted input",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Path Traversal / File Write (CWE-22) ---
		{
			ID:            "py.open",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `(?:^|[^A-Za-z0-9_])open\(`,
			ObjectType:    "",
			MethodName:    "open",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File open with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.os.path.join",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `os\.path\.join\(`,
			ObjectType:    "",
			MethodName:    "os.path.join",
			DangerousArgs: []int{1},
			Severity:      rules.Medium,
			Description:   "File path construction with potentially tainted component",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Open Redirect (CWE-601) ---
		// Pattern anchored to bare-name `redirect(...)` or a qualified
		// `flask.redirect(...)` / `django.shortcuts.redirect(...)` call.
		// Previously the bare `redirect\(` regex collided with function
		// *definition* lines whose name happens to contain the substring
		// "redirect" (e.g. `def get_login_redirect(request, default=None):`),
		// which the cross-file regex walker then treated as a sink call.
		// Sentry's `get_login_redirect` and `_get_login_redirect` lit this
		// up. The `\bredirect\s*\(` shape (with the explicit word boundary
		// and disallowed `def ` prefix) is the minimum fix.
		{
			ID:            "py.redirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangPython,
			Pattern:       `(?:^|[^A-Za-z0-9_])redirect\s*\(`,
			ObjectType:    "",
			MethodName:    "redirect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HTTP redirect with potentially tainted URL",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Template Injection (CWE-1336) ---
		{
			ID:            "py.render_template_string",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `render_template_string\(`,
			ObjectType:    "",
			MethodName:    "render_template_string",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Server-side template injection via tainted template string",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.jinja.template",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `Template\(`,
			ObjectType:    "jinja2",
			MethodName:    "Template",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Jinja2 template construction with potentially tainted string",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Template Path Traversal (CWE-22) ---
		{
			ID:            "py.flask.render_template",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `render_template\(`,
			ObjectType:    "flask",
			MethodName:    "render_template",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Flask render_template with potentially tainted template name (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.flask.send_file",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `send_file\(`,
			ObjectType:    "flask",
			MethodName:    "send_file",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Flask send_file with potentially tainted path (arbitrary file read)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Deserialization (CWE-502) ---
		{
			ID:            "py.pickle.loads",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `pickle\.loads\(`,
			ObjectType:    "",
			MethodName:    "pickle.loads",
			Module:        "pickle",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Pickle deserialization of potentially tainted data",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
			Advisory:      "CWE-502 / CPython pickle docs warning — pickle.loads() executes arbitrary code embedded in the byte stream (RCE)",
			AdvisoryID:    "CWE-502",
		},
		{
			ID:            "py.yaml.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `yaml\.load\(`,
			ObjectType:    "",
			MethodName:    "yaml.load",
			Module:        "yaml",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "YAML deserialization of potentially tainted data (unsafe loader)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
			Advisory:      "CVE-2017-18342 (PyYAML) — yaml.load() without SafeLoader instantiates arbitrary Python objects (RCE); use yaml.safe_load()",
			AdvisoryID:    "CVE-2017-18342",
		},

		// --- SSRF (CWE-918) ---
		// Receiver-scoping note (PR-CAT2py): the bare-`.get(` shape collides
		// with everyday dict/Mapping `.get(...)` lookups (`request.GET.get`,
		// `params.get`, `response_json.get`, `cache.get`, etc.). The Sentry
		// triage attributed ~25/80 cross-file false positives to this single
		// collision. We pin the HTTP-client `.get/.post/...` sinks to their
		// module names via Module + RequireModule so tsflow's matcher (and
		// the cross-file regex walker via the textual `module` gate) reject
		// calls whose receiver isn't the `requests` module itself.
		{
			ID:            "py.requests.get",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `requests\.get\(`,
			ObjectType:    "requests",
			MethodName:    "requests.get",
			Module:        "requests",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HTTP request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "py.urllib.urlopen",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `urllib\.request\.urlopen\(`,
			ObjectType:    "urllib.request",
			MethodName:    "urlopen",
			Module:        "urllib",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "URL open with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- XSS / HTML Output (CWE-79) ---
		{
			ID:            "py.send",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `\.send\(|make_response\(`,
			ObjectType:    "",
			MethodName:    "send/make_response",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "HTTP response with potentially tainted content (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- HTTP Header Injection (CWE-113) ---
		{
			ID:            "py.response.set_cookie",
			Category:      taint.SnkHeader,
			Language:      rules.LangPython,
			Pattern:       `\.set_cookie\(`,
			ObjectType:    "",
			MethodName:    "set_cookie",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Cookie set with potentially tainted value",
			CWEID:         "CWE-113",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- LDAP Injection (CWE-90) ---
		{
			ID:            "py.ldap.search",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.search_s\(`,
			ObjectType:    "ldap",
			MethodName:    "search_s",
			DangerousArgs: []int{0, 2},
			Severity:      rules.High,
			Description:   "LDAP search with potentially tainted filter",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		// ldap3 connection.search(...): the bare `\.search\(` regex was
		// catching every regex `.search(...)` (FUNCTION_PATTERN.search,
		// _release_suffix.search), every list `.search(...)` method and
		// every Elasticsearch/Marshmallow `.search(...)` chain. Anchor to
		// ldap-conventional receiver names. Same shape as the
		// py.cursor.execute tightening above.
		{
			ID:            "py.ldap3.search",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\b(?:ldap|conn|connection|ldap_conn|ld|c)\.search\(`,
			ObjectType:    "connection",
			MethodName:    "search",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "LDAP search with potentially tainted filter (ldap3)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		// python-ldap synchronous methods — the `_s`/`_ext_s` suffix is
		// distinctive to python-ldap SimpleLDAPObject and uncommon elsewhere.
		// python-ldap extended/sync search variants (CWE-90)
		{
			ID:            "py.ldap.search_ext_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.search_ext_s\(`,
			ObjectType:    "connection",
			MethodName:    "search_ext_s",
			DangerousArgs: []int{0, 2},
			Severity:      rules.High,
			Description:   "python-ldap extended synchronous search with tainted DN or filter",
		},

		{
			ID:            "py.ldap.add_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.add_s\(`,
			ObjectType:    "connection",
			MethodName:    "add_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap add_s with tainted DN (LDAP DN injection)",
		},
		{
			ID:            "py.ldap.search_st",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.search_st\(`,
			ObjectType:    "ldap",
			MethodName:    "search_st",
			DangerousArgs: []int{0, 2},
			Severity:      rules.High,
			Description:   "python-ldap sync search with timeout and potentially tainted base DN or filter",
		},
		{
			ID:            "py.ldap.search_st.bare",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.search_st\s*\(`,
			ObjectType:    "",
			MethodName:    "search_st",
			DangerousArgs: []int{0, 2},
			Severity:      rules.High,
			Description:   "python-ldap synchronous search with timeout and tainted base DN or filter",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		// python-ldap bind operations — DN injection via crafted authentication DN (CWE-90)
		{
			ID:            "py.ldap.bind_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.bind_s\(`,
			ObjectType:    "ldap",
			MethodName:    "bind_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap sync bind with potentially tainted DN (LDAP DN injection)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.ldap.add_ext_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.add_ext_s\(`,
			ObjectType:    "connection",
			MethodName:    "add_ext_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap add_ext_s with tainted DN (LDAP DN injection)",
		},
		{
			ID:            "py.ldap.simple_bind_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.simple_bind_s\(`,
			ObjectType:    "ldap",
			MethodName:    "simple_bind_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap sync simple_bind with potentially tainted DN (LDAP DN injection)",
		},
		{
			ID:            "py.ldap.simple_bind_s.bare",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.simple_bind_s\s*\(`,
			ObjectType:    "",
			MethodName:    "simple_bind_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap simple bind with tainted bind DN enables LDAP injection or auth bypass",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		{
			ID:            "py.ldap.bind_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.bind_s\s*\(`,
			ObjectType:    "",
			MethodName:    "bind_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap bind with tainted bind DN enables LDAP injection or auth bypass",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		{
			ID:            "py.ldap.sasl_interactive_bind_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.sasl_interactive_bind_s\s*\(`,
			ObjectType:    "",
			MethodName:    "sasl_interactive_bind_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap SASL interactive bind with tainted bind DN enables LDAP injection",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		// python-ldap modification operations — DN injection (CWE-90)
		{
			ID:            "py.ldap.modify_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.modify_s\(`,
			ObjectType:    "connection",
			MethodName:    "modify_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap modify_s with tainted DN (LDAP DN injection)",
		},

		{
			ID:            "py.ldap.modify_ext_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.modify_ext_s\(`,
			ObjectType:    "connection",
			MethodName:    "modify_ext_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap modify_ext_s with tainted DN (LDAP DN injection)",
		},
		{
			ID:            "py.ldap.modify_ext_s.bare",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.modify_ext_s\s*\(`,
			ObjectType:    "",
			MethodName:    "modify_ext_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap extended synchronous modify with tainted DN enables LDAP DN injection",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		{
			ID:            "py.ldap.add_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.add_s\(`,
			ObjectType:    "ldap",
			MethodName:    "add_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap sync add with potentially tainted DN (LDAP DN injection)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		{
			ID:            "py.ldap.delete_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.delete_s\(`,
			ObjectType:    "connection",
			MethodName:    "delete_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap delete_s with tainted DN (LDAP DN injection)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		{
			ID:            "py.ldap.delete_ext_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.delete_ext_s\(`,
			ObjectType:    "connection",
			MethodName:    "delete_ext_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap delete_ext_s with tainted DN (LDAP DN injection)",
		},

		{
			ID:            "py.ldap.compare_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.compare_s\(`,
			ObjectType:    "connection",
			MethodName:    "compare_s",
			DangerousArgs: []int{0, 2},
			Severity:      rules.High,
			Description:   "python-ldap compare_s with tainted DN or attribute value",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		{
			ID:            "py.ldap.compare_ext_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.compare_ext_s\(`,
			ObjectType:    "connection",
			MethodName:    "compare_ext_s",
			DangerousArgs: []int{0, 2},
			Severity:      rules.High,
			Description:   "python-ldap compare_ext_s with tainted DN or attribute value",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.ldap.modrdn_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.modrdn_s\(`,
			ObjectType:    "connection",
			MethodName:    "modrdn_s",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "python-ldap modrdn_s rename with tainted DN or new RDN (LDAP DN injection)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		{
			ID:            "py.ldap.rename_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.rename_s\(`,
			ObjectType:    "connection",
			MethodName:    "rename_s",
			DangerousArgs: []int{0, 1, 2},
			Severity:      rules.High,
			Description:   "python-ldap rename_s with tainted DN, new RDN, or new superior",
		},

		// Bare-receiver fallbacks for python-ldap _s methods: the python-ldap
		// idiom often binds the connection to a single-letter name like `l =
		// ldap.initialize(...)`, which doesn't trip the "connection" receiver
		// heuristic. The method names themselves (delete_s, modify_s,
		// compare_s, modrdn_s, rename_s) are distinctive enough to python-ldap
		// SimpleLDAPObject that bare-receiver matching is acceptable.
		{
			ID:            "py.ldap.delete_s.bare",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.delete_s\s*\(`,
			ObjectType:    "",
			MethodName:    "delete_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap delete_s with tainted DN (LDAP DN injection)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.ldap.modify_s.bare",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.modify_s\s*\(`,
			ObjectType:    "",
			MethodName:    "modify_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap modify_s with tainted DN (LDAP DN injection)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.ldap.compare_s.bare",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.compare_s\s*\(`,
			ObjectType:    "",
			MethodName:    "compare_s",
			DangerousArgs: []int{0, 2},
			Severity:      rules.High,
			Description:   "python-ldap compare_s with tainted DN or attribute value",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.ldap.modrdn_s.bare",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.modrdn_s\s*\(`,
			ObjectType:    "",
			MethodName:    "modrdn_s",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "python-ldap modrdn_s rename with tainted DN or new RDN (LDAP DN injection)",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.ldap.rename_s.bare",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.rename_s\s*\(`,
			ObjectType:    "",
			MethodName:    "rename_s",
			DangerousArgs: []int{0, 1, 2},
			Severity:      rules.High,
			Description:   "python-ldap rename_s with tainted DN, new RDN, or new superior",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		// ldap3 Connection.modify_dn — distinctive method name, DN injection (CWE-90)
		{
			ID:            "py.ldap3.modify_dn",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.modify_dn\(`,
			ObjectType:    "connection",
			MethodName:    "modify_dn",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "ldap3 Connection.modify_dn with potentially tainted DN or relative DN (LDAP DN injection)",
		},
		{
			ID:            "py.ldap.passwd_s",
			Category:      taint.SnkLDAP,
			Language:      rules.LangPython,
			Pattern:       `\.passwd_s\s*\(`,
			ObjectType:    "",
			MethodName:    "passwd_s",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "python-ldap synchronous password modify with tainted user DN enables LDAP DN injection",
			CWEID:         "CWE-90",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- SQLAlchemy SQL Injection (CWE-89) ---
		// Pattern intentionally requires an explicit `sqlalchemy.` / `sa.` /
		// `sqla.` qualifier — the bare `text(` form would mis-match any
		// callable named `text` (Django config dicts, JSON template field
		// accessors, etc.) and produced widespread false positives at the
		// cross-file boundary (see Sentry get_client_config/generate_context
		// findings). Users who `from sqlalchemy import text` and call bare
		// `text("SELECT ...")` will be missed by this entry, but the
		// downstream `engine/connection/session.execute(...)` sink still
		// fires when the resulting object is executed, so coverage is
		// preserved on the dangerous path.
		{
			ID:            "py.sqlalchemy.text",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\b(?:sqlalchemy|sqla|sa)\.text\s*\(`,
			ObjectType:    "sqlalchemy",
			MethodName:    "sqlalchemy.text",
			Module:        "sqlalchemy",
			RequireModule: false, // pattern already requires the qualifier inline
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQLAlchemy text() with potentially tainted raw SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.sqlalchemy.engine.execute",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `engine\.execute\(|connection\.execute\(|session\.execute\(`,
			ObjectType:    "sqlalchemy.engine",
			MethodName:    "execute",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQLAlchemy engine/connection/session execute with potentially tainted SQL",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Django ORM Raw SQL (CWE-89) ---
		// ObjectType was "django.db.models.Manager" — a framework type name no
		// real receiver expression ever carries. Django raw() is always invoked
		// as `<Model>.objects.raw(...)` (or on a queryset/related manager), so
		// the receiver of the `.raw(` call is `<Model>.objects`, never a variable
		// typed "Manager" — the structural matcher's receiver heuristics could
		// never bridge `login.objects` → "django.db.models.Manager", leaving the
		// sink permanently dead (pygoat `login.objects.raw(sql_query)` was 0
		// dataflow findings). Flip to wildcard ObjectType ("") and let the
		// `.objects.raw(` Pattern keep the match tight: a bare-name `.raw(` on a
		// non-ORM object (e.g. requests' `response.raw`) is an attribute, not a
		// call with `.objects.` in front, and weakSinkPatternOK re-validates the
		// call-node text against this Pattern before accepting the weak match.
		{
			ID:            "py.django.orm.raw",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.objects\.raw\(`,
			ObjectType:    "",
			MethodName:    "raw",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Django ORM raw() SQL query with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.django.orm.extra",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.extra\(`,
			ObjectType:    "django.db.models.QuerySet",
			MethodName:    "extra",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Django ORM extra() with potentially tainted SQL fragments",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.django.orm.rawsql",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `RawSQL\(`,
			ObjectType:    "django.db.models.expressions",
			MethodName:    "RawSQL",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Django RawSQL expression with potentially tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- DuckDB SQL Injection (CWE-89) ---
		// DuckDB's Python client exposes module-level and connection-level SQL
		// execution helpers that accept raw SQL strings. Parameterized values must
		// be passed via the `parameters` kwarg; interpolation into the SQL string
		// itself is injectable. Ref: https://duckdb.org/docs/api/python/dbapi
		{
			ID:            "py.duckdb.sql",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `duckdb\.sql\s*\(`,
			ObjectType:    "duckdb",
			MethodName:    "sql",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DuckDB duckdb.sql() with potentially tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.duckdb.execute",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `duckdb\.execute\s*\(`,
			ObjectType:    "duckdb",
			MethodName:    "execute",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DuckDB duckdb.execute() with potentially tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.duckdb.query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `duckdb\.query\s*\(`,
			ObjectType:    "duckdb",
			MethodName:    "query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DuckDB duckdb.query() with potentially tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.duckdb.connection.sql",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.sql\s*\(`,
			ObjectType:    "DuckDBPyConnection",
			MethodName:    "sql",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DuckDB connection.sql() with potentially tainted SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- ClickHouse SQL Injection (CWE-89) ---
		// ClickHouse is a widely used OLAP database. Two Python clients dominate:
		//   * clickhouse-connect (official, ClickHouse Inc.): a `Client` whose
		//     query_df/query_np/query_arrow/raw_query/command methods take the raw
		//     SQL string as the first positional arg. Safe parameterization uses the
		//     `parameters=` kwarg with server-side {name:Type} binding.
		//   * clickhouse-driver (native protocol): a `Client` whose
		//     execute/execute_iter/execute_with_progress take the SQL string as arg 0.
		//     Safe parameterization uses the `params=` kwarg with %(name)s placeholders.
		// In both, building the query with f-strings/concatenation is SQL injection —
		// the official docs explicitly warn about this.
		// Refs:
		//   https://clickhouse.com/docs/integrations/python
		//   https://clickhouse-driver.readthedocs.io/en/latest/quickstart.html
		//
		// NOTE: the plain `.query(` method (clickhouse-connect) is intentionally NOT
		// added here — for the canonical `client.query(...)` receiver it is already
		// caught (as CWE-89) by the bigquery.Client `query` sink, and a generic
		// `query`/ObjectType:"" entry would be far too broad. These entries target
		// the ClickHouse-specific method names that nothing else covers, plus the
		// `client`-scoped `command`/`execute` methods.
		{
			ID:            "py.clickhouse_connect.query_df",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.query_df\s*\(`,
			ObjectType:    "",
			MethodName:    "query_df",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "clickhouse-connect Client.query_df() runs raw SQL (returns a DataFrame); tainted first arg is SQL injection. Use the parameters= kwarg with {name:Type} binding.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.clickhouse_connect.query_np",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.query_np\s*\(`,
			ObjectType:    "",
			MethodName:    "query_np",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "clickhouse-connect Client.query_np() runs raw SQL (returns a numpy array); tainted first arg is SQL injection. Use the parameters= kwarg with {name:Type} binding.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.clickhouse_connect.query_arrow",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.query_arrow\s*\(`,
			ObjectType:    "",
			MethodName:    "query_arrow",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "clickhouse-connect Client.query_arrow() runs raw SQL (returns a PyArrow table); tainted first arg is SQL injection. Use the parameters= kwarg with {name:Type} binding.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.clickhouse_connect.raw_query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.raw_query\s*\(`,
			ObjectType:    "",
			MethodName:    "raw_query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "clickhouse-connect Client.raw_query() runs raw SQL and returns the unparsed response; tainted first arg is SQL injection. Use the parameters= kwarg with {name:Type} binding.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.clickhouse_connect.command",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `(?:client|ch_client|clickhouse_client|ch)\.command\s*\(`,
			ObjectType:    "Client",
			MethodName:    "command",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "clickhouse-connect Client.command() executes a SQL command/DDL string (arg 0); tainted input is SQL injection. Use the parameters= kwarg with {name:Type} binding.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.clickhouse_driver.execute",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `(?:client|ch_client|clickhouse_client|ch)\.execute\s*\(`,
			ObjectType:    "Client",
			MethodName:    "execute",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "clickhouse-driver Client.execute() runs a raw SQL string (arg 0); tainted input via f-string/concat is SQL injection. Use the params= kwarg with %(name)s placeholders.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.clickhouse_driver.execute_iter",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.execute_iter\s*\(`,
			ObjectType:    "",
			MethodName:    "execute_iter",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "clickhouse-driver Client.execute_iter() streams results for a raw SQL string (arg 0); tainted input is SQL injection. Use the params= kwarg with %(name)s placeholders.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.clickhouse_driver.execute_with_progress",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.execute_with_progress\s*\(`,
			ObjectType:    "",
			MethodName:    "execute_with_progress",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "clickhouse-driver Client.execute_with_progress() runs a raw SQL string (arg 0) with progress reporting; tainted input is SQL injection. Use the params= kwarg with %(name)s placeholders.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Polars SQL Injection (CWE-89) ---
		// Polars' read_database() and read_database_uri() take a SQL query as the
		// first positional argument. Parameterization is provided via separate
		// arguments; string interpolation is injectable.
		// Ref: https://docs.pola.rs/api/python/stable/reference/api/polars.read_database.html
		{
			ID:            "py.polars.read_database",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `pl\.read_database\s*\(|polars\.read_database\s*\(`,
			ObjectType:    "",
			MethodName:    "read_database",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Polars read_database() executes SQL — tainted first arg leads to SQL injection",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.polars.read_database_uri",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `pl\.read_database_uri\s*\(|polars\.read_database_uri\s*\(`,
			ObjectType:    "",
			MethodName:    "read_database_uri",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Polars read_database_uri() executes SQL — tainted first arg leads to SQL injection",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Django HttpResponse XSS (CWE-79) ---
		{
			ID:            "py.django.httpresponse",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `HttpResponse\(`,
			ObjectType:    "django.http",
			MethodName:    "HttpResponse",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Django HttpResponse with potentially tainted content (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Jinja2 |safe bypass (CWE-79) ---
		{
			ID:            "py.jinja2.markup",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `Markup\(`,
			ObjectType:    "markupsafe",
			MethodName:    "Markup",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Markup() marks string as safe HTML, bypassing auto-escaping (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.jinja2.markup.format",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `Markup\.format\(`,
			ObjectType:    "markupsafe",
			MethodName:    "Markup.format",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Markup.format() interpolates into safe HTML string, bypassing auto-escaping (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Django mark_safe (CWE-79) ---
		{
			ID:            "py.django.mark_safe",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `mark_safe\(`,
			ObjectType:    "django.utils.safestring",
			MethodName:    "mark_safe",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Django mark_safe() marks string as safe HTML, bypassing auto-escaping (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Weak Crypto (CWE-328) ---
		{
			ID:            "py.hashlib.md5",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `hashlib\.md5\(`,
			ObjectType:    "hashlib",
			MethodName:    "md5",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Use of weak MD5 hash for potentially security-sensitive data",
			CWEID:         "CWE-328",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "py.hashlib.sha1",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `hashlib\.sha1\(`,
			ObjectType:    "hashlib",
			MethodName:    "sha1",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Use of weak SHA1 hash for potentially security-sensitive data",
			CWEID:         "CWE-328",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "py.random.weak",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `random\.random\(|random\.randint\(|random\.choice\(`,
			ObjectType:    "random",
			MethodName:    "random.*",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Non-cryptographic random used where secrets module should be used",
			CWEID:         "CWE-330",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// --- XML External Entity (CWE-611) ---
		{
			ID:            "py.xml.etree.parse",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `xml\.etree\.ElementTree\.parse\(|ET\.parse\(|ElementTree\.parse\(`,
			ObjectType:    "xml.etree.ElementTree",
			MethodName:    "parse",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XML parsing of potentially tainted data (XXE risk)",
			CWEID:         "CWE-611",
			OWASPCategory: "A05:2021-Security Misconfiguration",
		},
		{
			ID:            "py.xml.etree.fromstring",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `xml\.etree\.ElementTree\.fromstring\(|ET\.fromstring\(`,
			ObjectType:    "xml.etree.ElementTree",
			MethodName:    "fromstring",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "XML string parsing of potentially tainted data (XXE risk)",
			CWEID:         "CWE-611",
			OWASPCategory: "A05:2021-Security Misconfiguration",
		},
		// lxml is the dominant third-party XML parser and — unlike the
		// stdlib etree entries above — resolves external entities and the
		// DOCTYPE by default unless the caller passes a hardened
		// XMLParser(resolve_entities=False, no_network=True). A tainted
		// document into lxml.etree.parse/fromstring/XML is therefore a
		// direct XXE (file read, SSRF, billion-laughs) vector. Anchor to
		// the `lxml`-qualified form so we don't double-fire on the stdlib
		// etree entries above and keep FPs at zero.
		{
			ID:            "py.lxml.etree.parse",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `lxml\.etree\.parse\s*\(`,
			ObjectType:    "lxml.etree",
			MethodName:    "parse",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "lxml.etree.parse of potentially tainted XML — lxml resolves external entities by default (XXE: file read, SSRF, billion-laughs). Pass a hardened XMLParser(resolve_entities=False, no_network=True).",
			CWEID:         "CWE-611",
			OWASPCategory: "A05:2021-Security Misconfiguration",
		},
		{
			ID:            "py.lxml.etree.fromstring",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `lxml\.etree\.fromstring\s*\(|lxml\.etree\.XML\s*\(`,
			ObjectType:    "lxml.etree",
			MethodName:    "fromstring",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "lxml.etree.fromstring/XML of potentially tainted XML — lxml resolves external entities by default (XXE). Pass a hardened XMLParser(resolve_entities=False, no_network=True).",
			CWEID:         "CWE-611",
			OWASPCategory: "A05:2021-Security Misconfiguration",
		},
		// xml.dom.minidom shares the stdlib expat parser; parseString /
		// parse resolves a tainted DOCTYPE's external/parameter entities
		// (XXE) unless the caller swaps in a defused parser
		// (defusedxml.minidom). Anchor to the `minidom.`-qualified call.
		{
			ID:            "py.xml.dom.minidom.parseString",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `(?:xml\.dom\.)?minidom\.parseString\s*\(|(?:xml\.dom\.)?minidom\.parse\s*\(`,
			ObjectType:    "xml.dom.minidom",
			MethodName:    "parseString",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "xml.dom.minidom.parseString/parse of potentially tainted XML (XXE: entity resolution via expat). Use defusedxml.minidom for untrusted input.",
			CWEID:         "CWE-611",
			OWASPCategory: "A05:2021-Security Misconfiguration",
		},
		// xml.sax.parse / parseString feeds a tainted document into a SAX
		// reader whose default feature flags resolve external entities
		// (XXE). Anchor to the `sax.`-qualified call so we don't collide
		// with unrelated `.parse(` methods.
		{
			ID:            "py.xml.sax.parse",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `(?:xml\.)?sax\.parseString\s*\(|(?:xml\.)?sax\.parse\s*\(`,
			ObjectType:    "xml.sax",
			MethodName:    "parse",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "xml.sax.parse/parseString of potentially tainted XML (XXE: SAX reader resolves external entities by default). Use defusedxml.sax for untrusted input.",
			CWEID:         "CWE-611",
			OWASPCategory: "A05:2021-Security Misconfiguration",
		},

		// --- Marshal Deserialization (CWE-502) ---
		{
			ID:            "py.marshal.loads",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `marshal\.loads\(|marshal\.load\(`,
			ObjectType:    "",
			MethodName:    "marshal.loads",
			Module:        "marshal",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Marshal deserialization of potentially tainted data (code execution risk)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- Weak Encryption Algorithm (CWE-327) ---
		{
			ID:            "py.crypto.des",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `DES\.new\(|DES3\.new\(|Crypto\.Cipher\.DES`,
			ObjectType:    "Crypto.Cipher",
			MethodName:    "DES.new",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "DES/3DES cipher usage (weak, use AES instead)",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "py.crypto.ecb_mode",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `AES\.new\(.*MODE_ECB|DES\.new\(.*MODE_ECB|mode\s*=\s*AES\.MODE_ECB`,
			ObjectType:    "Crypto.Cipher",
			MethodName:    "ECB mode",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "ECB mode cipher usage (no diffusion, use CBC/GCM instead)",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "py.crypto.rc4",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `ARC4\.new\(|Crypto\.Cipher\.ARC4`,
			ObjectType:    "Crypto.Cipher",
			MethodName:    "ARC4.new",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "RC4 stream cipher usage (broken, use AES-GCM instead)",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// --- JWT Without Verification (CWE-345) ---
		{
			ID:            "py.jwt.decode.noverify",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `jwt\.decode\(.*verify\s*=\s*False|jwt\.decode\(.*options.*verify`,
			ObjectType:    "jwt",
			MethodName:    "jwt.decode (no verify)",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "JWT decoded without signature verification",
			CWEID:         "CWE-345",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// --- Redis Command Injection (CWE-77) ---
		{
			ID:            "py.redis.execute_command",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `\.execute_command\(`,
			ObjectType:    "redis.Redis",
			MethodName:    "execute_command",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Redis command execution with potentially tainted arguments",
			CWEID:         "CWE-77",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.redis.eval",
			Category:      taint.SnkEval,
			Language:      rules.LangPython,
			Pattern:       `\.eval\(\s*['""]|redis_client\.eval\(`,
			ObjectType:    "redis.Redis",
			MethodName:    "eval",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Redis Lua script evaluation with potentially tainted script",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- SMTP Header Injection (CWE-93) ---
		{
			ID:            "py.smtplib.sendmail",
			Category:      taint.SnkHeader,
			Language:      rules.LangPython,
			Pattern:       `smtplib\.SMTP.*\.sendmail\(|\.sendmail\(`,
			ObjectType:    "smtplib.SMTP",
			MethodName:    "sendmail",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "SMTP sendmail with potentially tainted headers/recipients",
			CWEID:         "CWE-93",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- DNS Lookup with Tainted Hostname (CWE-918) ---
		{
			ID:            "py.socket.getaddrinfo",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `socket\.getaddrinfo\(|socket\.gethostbyname\(`,
			ObjectType:    "socket",
			MethodName:    "getaddrinfo/gethostbyname",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "DNS lookup with potentially tainted hostname (SSRF/DNS rebinding)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- Docker Exec (CWE-78) ---
		{
			ID:            "py.docker.exec_run",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `\.exec_run\(|container\.exec_run\(`,
			ObjectType:    "docker.models.containers.Container",
			MethodName:    "exec_run",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Docker container exec with potentially tainted command",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Kafka Message Construction (CWE-77) ---
		{
			ID:            "py.kafka.send",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `producer\.send\(|\.send\(\s*['"]`,
			ObjectType:    "kafka.KafkaProducer",
			MethodName:    "send",
			DangerousArgs: []int{1},
			Severity:      rules.Medium,
			Description:   "Kafka message produced with potentially tainted data",
			CWEID:         "CWE-77",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Log Injection (CWE-117) ---
		{
			ID:            "py.logging.info",
			Category:      taint.SnkLog,
			Language:      rules.LangPython,
			Pattern:       `logging\.info\(`,
			ObjectType:    "logging",
			MethodName:    "info",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Logging info with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "py.logging.warning",
			Category:      taint.SnkLog,
			Language:      rules.LangPython,
			Pattern:       `logging\.warning\(`,
			ObjectType:    "logging",
			MethodName:    "warning",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Logging warning with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "py.logging.error",
			Category:      taint.SnkLog,
			Language:      rules.LangPython,
			Pattern:       `logging\.error\(`,
			ObjectType:    "logging",
			MethodName:    "error",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Logging error with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "py.logging.debug",
			Category:      taint.SnkLog,
			Language:      rules.LangPython,
			Pattern:       `logging\.debug\(`,
			ObjectType:    "logging",
			MethodName:    "debug",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Logging debug with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "py.logging.critical",
			Category:      taint.SnkLog,
			Language:      rules.LangPython,
			Pattern:       `logging\.critical\(`,
			ObjectType:    "logging",
			MethodName:    "critical",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Logging critical with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "py.logger.info",
			Category:      taint.SnkLog,
			Language:      rules.LangPython,
			Pattern:       `logger\.info\(`,
			ObjectType:    "Logger",
			MethodName:    "info",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Logger info with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "py.logger.warning",
			Category:      taint.SnkLog,
			Language:      rules.LangPython,
			Pattern:       `logger\.warning\(`,
			ObjectType:    "Logger",
			MethodName:    "warning",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Logger warning with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "py.logger.error",
			Category:      taint.SnkLog,
			Language:      rules.LangPython,
			Pattern:       `logger\.error\(`,
			ObjectType:    "Logger",
			MethodName:    "error",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Logger error with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},
		{
			ID:            "py.logger.debug",
			Category:      taint.SnkLog,
			Language:      rules.LangPython,
			Pattern:       `logger\.debug\(`,
			ObjectType:    "Logger",
			MethodName:    "debug",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Logger debug with potentially tainted data (log injection)",
			CWEID:         "CWE-117",
			OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
		},

		// --- Symlink Creation (CWE-59) ---
		{
			ID:            "py.os.symlink",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `os\.symlink\(`,
			ObjectType:    "",
			MethodName:    "os.symlink",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Symlink creation with potentially tainted path (symlink attack)",
			CWEID:         "CWE-59",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Directory Creation (CWE-22) ---
		{
			ID:            "py.os.makedirs",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `os\.makedirs\(|os\.mkdir\(`,
			ObjectType:    "",
			MethodName:    "os.makedirs/mkdir",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Directory creation with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- File Rename / Path Construction (CWE-73) ---
		{
			ID:            "py.os.rename",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `os\.rename\(|os\.renames\(|os\.replace\(`,
			ObjectType:    "",
			MethodName:    "os.rename/renames/replace",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "File rename/replace with potentially tainted path (external control of file name)",
			CWEID:         "CWE-73",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.os.link",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `os\.link\(`,
			ObjectType:    "",
			MethodName:    "os.link",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Hard link creation with potentially tainted path (external control of file name)",
			CWEID:         "CWE-73",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		// --- File Copy/Move / Path Construction (CWE-73) ---
		{
			ID:            "py.shutil.copy",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `shutil\.copy\(|shutil\.copy2\(|shutil\.copyfile\(|shutil\.move\(|shutil\.copytree\(`,
			ObjectType:    "",
			MethodName:    "shutil.copy/copy2/copyfile/move/copytree",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "File copy/move with potentially tainted source or destination path (external control of file name)",
			CWEID:         "CWE-73",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- ReDoS (CWE-1333) ---
		// Regex execution on attacker-controlled patterns is a Regular
		// Expression Denial of Service concern (CWE-1333 / CWE-400), not
		// dynamic code injection (CWE-94). Classify under SnkRegexDoS so
		// the interprocedural rule ID becomes BATOU-INTERPROC-REGEX_DOS
		// (medium-severity DoS) instead of BATOU-INTERPROC-CODE_EVAL
		// (critical-severity RCE) — see Sentry parse_stats_period
		// findings.
		//
		// DangerousArgs note (PR-CAT2py): pattern is *always* arg 0 in
		// the re.* family — re.compile(p), re.match(p, s), re.search(p, s),
		// re.fullmatch(p, s), re.findall(p, s), re.finditer(p, s),
		// re.sub(p, r, s), re.subn(p, r, s), re.split(p, s). The string
		// being scanned (arg 1+) is the *haystack* — having user input
		// in the haystack is the whole point of regex matching and
		// should NEVER fire the ReDoS sink. Keeping DangerousArgs=[0]
		// ensures the catalog reflects this.
		{
			ID:            "py.re.compile",
			Category:      taint.SnkRegexDoS,
			Language:      rules.LangPython,
			Pattern:       `re\.compile\(|re\.match\(|re\.search\(|re\.findall\(|re\.fullmatch\(|re\.finditer\(|re\.sub\(|re\.subn\(|re\.split\(`,
			ObjectType:    "re",
			MethodName:    "compile/match/search/findall/fullmatch/finditer/sub/subn/split",
			Module:        "re",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Regex compilation/execution with potentially tainted pattern (ReDoS) — pattern is positional arg 0; the haystack/replacement is never the dangerous argument",
			CWEID:         "CWE-1333",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		// The PyPI `regex` module (https://pypi.org/project/regex/, ~30M
		// downloads/month) is a drop-in replacement for stdlib `re` exposing the
		// same top-level API (compile/match/search/findall/fullmatch/finditer/
		// sub/subn/split) and the same NFA backtracking engine — so a tainted
		// pattern is just as ReDoS-exploitable as with `re`. The `py.re.compile`
		// entry above is scoped to ObjectType/Module "re" and therefore never
		// fires on `regex.<fn>(...)`. Same FP discipline as the `re` entry:
		// pattern is positional arg 0, and Module+RequireModule confines the
		// match to module-level `regex.<fn>(...)` calls.
		{
			ID:            "py.regex.compile",
			Category:      taint.SnkRegexDoS,
			Language:      rules.LangPython,
			Pattern:       `\bregex\.compile\(|\bregex\.match\(|\bregex\.search\(|\bregex\.findall\(|\bregex\.fullmatch\(|\bregex\.finditer\(|\bregex\.sub\(|\bregex\.subn\(|\bregex\.split\(`,
			ObjectType:    "regex",
			MethodName:    "compile/match/search/findall/fullmatch/finditer/sub/subn/split",
			Module:        "regex",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Third-party regex module regex compilation/execution with potentially tainted pattern (ReDoS) — pattern is positional arg 0; the haystack/replacement is never the dangerous argument",
			CWEID:         "CWE-1333",
			OWASPCategory: "A04:2021-Insecure Design",
		},

		// --- Third-party `regex` package ReDoS (CWE-1333) ---
		// The PyPI `regex` module (https://pypi.org/project/regex/, tens of
		// millions of downloads/month) is a drop-in replacement for the stdlib
		// `re` with an identical module-level API, but a fully *backtracking*
		// engine that is, if anything, more prone to catastrophic backtracking
		// than `re` (it adds recursive patterns, possessive quantifiers, and
		// fuzzy matching). A user-controlled pattern compiled/executed by any
		// module-level regex.* function is a Regular Expression Denial of
		// Service (CWE-1333 / CWE-400), NOT dynamic code injection.
		//
		// Without this dedicated entry `regex.compile(tainted)` falls through to
		// the generic empty-ObjectType `py.compile` sink below and is
		// mis-reported as a Critical SnkEval / CWE-94 RCE. Scoping to
		// ObjectType "regex" is a *strong* receiver match, so the tsflow matcher
		// returns this entry ahead of the wildcard `py.compile` (which is only a
		// weak/deferred candidate) — reclassifying the flow as a Medium ReDoS.
		// stdlib `re.compile` is unaffected: it strong-matches the earlier
		// ObjectType "re" entry, never this one.
		//
		// DangerousArgs note: pattern is positional arg 0 in every module-level
		// regex.* function — regex.compile(p), regex.match(p, s),
		// regex.search(p, s), regex.sub(p, r, s), regex.split(p, s), … — the
		// string being scanned (arg 1+) is the haystack and must never fire.
		{
			ID:            "py.regex.compile",
			Category:      taint.SnkRegexDoS,
			Language:      rules.LangPython,
			Pattern:       `regex\.compile\(|regex\.match\(|regex\.search\(|regex\.fullmatch\(|regex\.findall\(|regex\.finditer\(|regex\.sub\(|regex\.subn\(|regex\.subf\(|regex\.subfn\(|regex\.split\(|regex\.splititer\(`,
			ObjectType:    "regex",
			MethodName:    "compile/match/search/fullmatch/findall/finditer/sub/subn/subf/subfn/split/splititer",
			Module:        "regex",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Third-party `regex` package compilation/execution with potentially tainted pattern (ReDoS) — `regex` is a backtracking drop-in for stdlib `re`; pattern is positional arg 0, the haystack/replacement is never the dangerous argument",
			CWEID:         "CWE-1333",
			OWASPCategory: "A04:2021-Insecure Design",
		},

		// --- Dynamic Import (CWE-94) ---
		{
			ID:            "py.importlib.import_module",
			Category:      taint.SnkEval,
			Language:      rules.LangPython,
			Pattern:       `importlib\.import_module\(|__import__\(`,
			ObjectType:    "",
			MethodName:    "importlib.import_module/__import__",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Dynamic module import with potentially tainted module name",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Compile (CWE-94) ---
		{
			ID:            "py.compile",
			Category:      taint.SnkEval,
			Language:      rules.LangPython,
			Pattern:       `(?:^|[^A-Za-z0-9_.])compile\(`,
			ObjectType:    "",
			MethodName:    "compile",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Code compilation with potentially tainted source string",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Shelve Deserialization (CWE-502) ---
		{
			ID:            "py.shelve.open",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `shelve\.open\(`,
			ObjectType:    "",
			MethodName:    "shelve.open",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Shelve deserialization from potentially tainted file path",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- Additional SSRF vectors (CWE-918) ---
		// Same receiver-scoping rationale as py.requests.get above —
		// bare `.post(`/`.put(`/`.delete(`/`.patch(` collides with
		// many ORM/Cache/SDK methods of the same name.
		{
			ID:            "py.requests.post",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `requests\.post\(|requests\.put\(|requests\.delete\(|requests\.patch\(`,
			ObjectType:    "requests",
			MethodName:    "requests.post/put/delete/patch",
			Module:        "requests",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HTTP request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- Jinja2 from_string (CWE-1336) ---
		{
			ID:            "py.jinja2.from_string",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `\.from_string\(`,
			ObjectType:    "jinja2.Environment",
			MethodName:    "from_string",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Jinja2 Environment.from_string with user-controlled template (SSTI)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- subprocess.Popen (CWE-78) ---
		{
			ID:            "py.subprocess.popen",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `subprocess\.Popen\(`,
			ObjectType:    "",
			MethodName:    "subprocess.Popen",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Subprocess Popen with potentially tainted command",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- paramiko exec_command (CWE-78) ---
		{
			ID:            "py.paramiko.exec_command",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `\.exec_command\(`,
			ObjectType:    "paramiko.SSHClient",
			MethodName:    "exec_command",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SSH command execution via paramiko with potentially tainted input",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- fabric run (CWE-78) ---
		{
			ID:            "py.fabric.run",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `fabric\..*\.run\(|c\.run\(|conn\.run\(`,
			ObjectType:    "fabric.Connection",
			MethodName:    "run",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Remote command execution via Fabric with tainted input",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- fabric Connection.sudo (CWE-78) ---
		// fabric.Connection.sudo(command) runs `sudo command` on the remote host.
		// A tainted command argument gives the attacker root-level RCE.
		{
			ID:            "py.fabric.sudo",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `fabric\..*\.sudo\(|c\.sudo\(|conn\.sudo\(`,
			ObjectType:    "fabric.Connection",
			MethodName:    "sudo",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Fabric Connection.sudo() executes a remote command as root with tainted input — RCE as root",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- fabric Connection.local (CWE-78) ---
		// fabric.Connection.local(command) runs the command on the local host
		// (Fabric 2.x via invoke). Tainted input enables local shell injection.
		{
			ID:            "py.fabric.local",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `fabric\..*\.local\(|c\.local\(|conn\.local\(`,
			ObjectType:    "fabric.Connection",
			MethodName:    "local",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Fabric Connection.local() runs a local shell command with tainted input — local command injection",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- paramiko SFTPClient.remove / unlink (CWE-22 / CWE-73) ---
		// paramiko.SFTPClient.remove(path) deletes a remote file. Tainted path
		// enables arbitrary remote file deletion.
		{
			ID:            "py.paramiko.sftp.remove",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `(?:sftp|paramiko\.SFTPClient.*)\.(?:remove|unlink)\s*\(`,
			ObjectType:    "paramiko.SFTPClient",
			MethodName:    "remove/unlink",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "paramiko SFTPClient.remove()/unlink() with tainted path — arbitrary remote file deletion",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- paramiko SFTPClient.rename (CWE-22) ---
		// paramiko.SFTPClient.rename(oldpath, newpath) and posix_rename do the
		// same. Either path being tainted enables arbitrary file move/overwrite.
		{
			ID:            "py.paramiko.sftp.rename",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `(?:sftp|paramiko\.SFTPClient.*)\.(?:rename|posix_rename)\s*\(`,
			ObjectType:    "paramiko.SFTPClient",
			MethodName:    "rename/posix_rename",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "paramiko SFTPClient.rename()/posix_rename() with tainted old/new path — arbitrary file move or overwrite",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- paramiko SFTPClient.symlink (CWE-59 / CWE-22) ---
		// paramiko.SFTPClient.symlink(source, dest) creates a remote symlink.
		// Attacker-controlled source/dest enables symlink-based attacks (e.g.
		// pointing a watched dest at /etc/passwd).
		{
			ID:            "py.paramiko.sftp.symlink",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `(?:sftp|paramiko\.SFTPClient.*)\.symlink\s*\(`,
			ObjectType:    "paramiko.SFTPClient",
			MethodName:    "symlink",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "paramiko SFTPClient.symlink() with tainted source/dest — symlink-following attacks against the SSH server",
			CWEID:         "CWE-59",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- paramiko SFTPClient.mkdir (CWE-22) ---
		// paramiko.SFTPClient.mkdir(path) creates a remote directory. Tainted
		// path enables arbitrary directory creation outside the intended root.
		{
			ID:            "py.paramiko.sftp.mkdir",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `(?:sftp|paramiko\.SFTPClient.*)\.mkdir\s*\(`,
			ObjectType:    "paramiko.SFTPClient",
			MethodName:    "mkdir",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "paramiko SFTPClient.mkdir() with tainted path — directory creation outside intended scope (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- asyncio.create_subprocess_shell (CWE-78) ---
		{
			ID:            "py.asyncio.create_subprocess_shell",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `asyncio\.create_subprocess_shell\(|create_subprocess_shell\(`,
			ObjectType:    "",
			MethodName:    "create_subprocess_shell",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Async subprocess with shell=True semantics — tainted cmd enables full shell injection",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- asyncio.create_subprocess_exec (CWE-78) ---
		{
			ID:            "py.asyncio.create_subprocess_exec",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `asyncio\.create_subprocess_exec\(|create_subprocess_exec\(`,
			ObjectType:    "",
			MethodName:    "create_subprocess_exec",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Async subprocess exec — no shell but tainted program path enables arbitrary binary execution",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- os.exec* family (CWE-78) ---
		{
			ID:            "py.os.execv",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `os\.exec[lv][p]?e?\(`,
			ObjectType:    "",
			MethodName:    "os.execl/os.execle/os.execlp/os.execlpe/os.execv/os.execve/os.execvp/os.execvpe",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Process replacement via os.exec* with potentially tainted path/args",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- os.spawn* family (CWE-78) ---
		{
			ID:            "py.os.spawnv",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `os\.spawn[lv][p]?e?\(`,
			ObjectType:    "",
			MethodName:    "os.spawnl/os.spawnle/os.spawnlp/os.spawnlpe/os.spawnv/os.spawnve/os.spawnvp/os.spawnvpe",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "Process spawning via os.spawn* with potentially tainted path (arg 1, after mode)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- pty.spawn (CWE-78) ---
		{
			ID:            "py.pty.spawn",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `pty\.spawn\(`,
			ObjectType:    "",
			MethodName:    "pty.spawn",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PTY spawn with potentially tainted argv — enables arbitrary command execution with full TTY",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Django render_to_string (PR-CAT2py) ---
		// Removed: previously `py.django.render_to_string` was a
		// SnkHTMLOutput sink whose DangerousArgs[0] was the template name.
		// Cross-file lifting promoted *any* taint passing through the call
		// to a HIGH-severity XSS finding, because the regex walker
		// matches on the sink line and treats every source-param token
		// appearance as a flow. Django templates auto-escape by default,
		// so context taint is neutralised by the template engine itself;
		// the moved sanitizer in python_sanitizers.go records that.
		// Template-name injection is a SnkTemplate (CWE-1336) concern and
		// is already covered by Jinja-from_string / template_name regex
		// rules — promoting render_to_string to a SnkTemplate sink here
		// would also flag the (vastly more common) safe-shape calls.
		// See the Sentry triage for the ~9 false positives this clears.

		// --- os.remove/unlink (CWE-22) ---
		{
			ID:            "py.os.remove",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `os\.remove\(|os\.unlink\(`,
			ObjectType:    "",
			MethodName:    "os.remove/unlink",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File deletion with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- pickle.load (CWE-502) ---
		{
			ID:            "py.pickle.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `pickle\.load\(`,
			ObjectType:    "",
			MethodName:    "pickle.load",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Pickle deserialization from file with potentially tainted data",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- dill deserialization (CWE-502) ---
		// dill extends pickle's object graph (closures, lambdas, class objects)
		// but inherits pickle's full RCE semantics: a crafted byte stream
		// triggers __reduce__ on unpickle and runs arbitrary code.
		{
			ID:            "py.dill.loads",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `dill\.loads\s*\(`,
			ObjectType:    "",
			MethodName:    "dill.loads",
			Module:        "dill",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "dill deserialization of potentially tainted bytes (pickle-compatible, arbitrary code execution)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.dill.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `dill\.load\s*\(`,
			ObjectType:    "",
			MethodName:    "dill.load",
			Module:        "dill",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "dill deserialization from file-like object (pickle-compatible, arbitrary code execution)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- cloudpickle deserialization (CWE-502) ---
		// cloudpickle is used by Ray, Dask, MLflow, Apache Spark (PySpark) to
		// ship Python closures between workers. Equally unsafe with untrusted
		// data — unpickle triggers arbitrary code execution.
		{
			ID:            "py.cloudpickle.loads",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `cloudpickle\.loads\s*\(`,
			ObjectType:    "",
			MethodName:    "cloudpickle.loads",
			Module:        "cloudpickle",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "cloudpickle deserialization of potentially tainted bytes (pickle-compatible, arbitrary code execution — used by Ray/Dask/MLflow)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.cloudpickle.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `cloudpickle\.load\s*\(`,
			ObjectType:    "",
			MethodName:    "cloudpickle.load",
			Module:        "cloudpickle",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "cloudpickle deserialization from file-like object (pickle-compatible, arbitrary code execution — used by Ray/Dask/MLflow)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- jsonpickle decode (CWE-502) ---
		// CVE-2020-22083: jsonpickle.decode() reconstructs arbitrary Python
		// objects from a JSON string and evaluates py/repr strings, allowing
		// remote code execution when the input is attacker-controlled.
		{
			ID:            "py.jsonpickle.decode",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `jsonpickle\.decode\s*\(`,
			ObjectType:    "",
			MethodName:    "jsonpickle.decode",
			Module:        "jsonpickle",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "jsonpickle.decode deserialization of tainted JSON string (CVE-2020-22083 — py/object directives enable RCE)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- joblib.load (CWE-502) ---
		// joblib.load uses pickle under the hood. scikit-learn models are
		// routinely saved with joblib.dump and loaded with joblib.load;
		// HuggingFace Transformers/SetFit issue #630 documents RCE via a
		// malicious model_head.pkl file. Any untrusted model path is dangerous.
		{
			ID:            "py.joblib.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `joblib\.load\s*\(`,
			ObjectType:    "",
			MethodName:    "joblib.load",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "joblib.load deserializes pickle-format model file; tainted path or bytes enables arbitrary code execution (scikit-learn/MLflow/HuggingFace models)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- xmlrpc.client deserialization (CWE-502) ---
		// xmlrpc.client.loads parses an XML-RPC response and constructs
		// Python objects. Historical RCE/XXE vector when parsing untrusted
		// XML payloads. xmlrpclib is the Python 2 module name — split into
		// its own entry below to keep the Module gate single-valued.
		//
		// Module-scoped (PR-CAT2py): bare `.loads(` matched `orjson.loads()`
		// / `json.loads()` against this XML-RPC sink. tsflow's matcher pins
		// the receiver to the xmlrpc module via Module + RequireModule; the
		// cross-file regex walker honours the same gate via its textual
		// `module` check.
		{
			ID:            "py.xmlrpc.client.loads",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `xmlrpc\.client\.loads\s*\(`,
			ObjectType:    "xmlrpc.client",
			MethodName:    "xmlrpc.client.loads",
			Module:        "xmlrpc",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "xmlrpc.client.loads deserializes XML-RPC payload; tainted input enables XXE and unsafe object construction",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.xmlrpclib.loads",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `xmlrpclib\.loads\s*\(`,
			ObjectType:    "xmlrpclib",
			MethodName:    "xmlrpclib.loads",
			Module:        "xmlrpclib",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "xmlrpclib.loads (Python 2) deserializes XML-RPC payload; tainted input enables XXE and unsafe object construction",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- torch.load (CWE-502) ---
		// torch.load() uses pickle internally by default. Loading an
		// attacker-controlled model file (.pt/.pth) runs arbitrary code on
		// the machine. Defense requires weights_only=True (PyTorch 2.6+).
		// Huge real-world vector via HuggingFace Hub / torch-hub model distribution.
		{
			ID:            "py.torch.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `torch\.load\s*\(`,
			ObjectType:    "",
			MethodName:    "torch.load",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "torch.load deserializes PyTorch model files via pickle; tainted path or bytes enables RCE unless weights_only=True is set",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- yaml.unsafe_load (CWE-502) ---
		{
			ID:            "py.yaml.unsafe_load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `yaml\.unsafe_load\(|yaml\.full_load\(`,
			ObjectType:    "",
			MethodName:    "yaml.unsafe_load/full_load",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "YAML deserialization with unsafe loader allowing arbitrary objects",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- aiohttp SSRF (CWE-918) ---
		// Pattern previously matched bare `session.get(` which catches
		// the wildly more common `request.session.get(...)` Django
		// session-dict shape. Anchor on `aiohttp.ClientSession(...)` /
		// `ClientSession()...` so the cross-file regex walker doesn't
		// surface Django session dict reads. RequireModule + Module
		// "aiohttp" enforces the same gate in the tsflow matcher (the
		// receiver's first dotted segment must literally be `aiohttp`).
		{
			ID:            "py.aiohttp.clientsession.get",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `aiohttp\.ClientSession\s*\([^)]*\)\.get\s*\(|ClientSession\s*\(\s*\)\.get\s*\(`,
			ObjectType:    "aiohttp.ClientSession",
			MethodName:    "get",
			Module:        "aiohttp",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "aiohttp client request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- httpx SSRF (CWE-918) ---
		{
			ID:            "py.httpx.get",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `httpx\.get\(|httpx\.post\(|httpx\.AsyncClient\(\)\.get\(`,
			ObjectType:    "httpx",
			MethodName:    "get/post",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "httpx HTTP request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- requests: missing HTTP verbs (CWE-918) ---
		// Module-scoped to the `requests` module — see py.requests.get
		// receiver-scoping note above.
		{
			ID:            "py.requests.head",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `requests\.head\(|requests\.options\(`,
			ObjectType:    "requests",
			MethodName:    "requests.head/options",
			Module:        "requests",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HTTP request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "py.requests.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `requests\.request\(`,
			ObjectType:    "requests",
			MethodName:    "requests.request",
			Module:        "requests",
			RequireModule: true,
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "HTTP request with potentially tainted URL (SSRF) — URL is 2nd arg after method",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "py.requests.session",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `requests\.Session\s*\(\s*\)\.(get|post|put|delete|patch|head|options|request)\s*\(`,
			ObjectType:    "requests.Session",
			MethodName:    "Session().get/post/...",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "HTTP request via requests.Session with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- urllib: additional vectors (CWE-918) ---
		// Module-scoped to `urllib` — `urlretrieve`/`Request` are not
		// unique enough to allow bare receiver matches.
		{
			ID:            "py.urllib.urlretrieve",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `urllib\.request\.urlretrieve\s*\(`,
			ObjectType:    "urllib.request",
			MethodName:    "urllib.request.urlretrieve",
			Module:        "urllib",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File download from tainted URL via urlretrieve (SSRF + arbitrary file write)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "py.urllib.request.constructor",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `urllib\.request\.Request\s*\(`,
			ObjectType:    "urllib.request",
			MethodName:    "urllib.request.Request",
			Module:        "urllib",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "URL request object with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- urllib3 (CWE-918) ---
		{
			ID:            "py.urllib3.poolmanager.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `urllib3\.PoolManager\s*\(.*\.request\s*\(|urllib3\.HTTPConnectionPool\s*\(.*\.request\s*\(|urllib3\.ProxyManager\s*\(.*\.request\s*\(`,
			ObjectType:    "urllib3",
			MethodName:    "PoolManager/HTTPConnectionPool/ProxyManager.request",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "urllib3 HTTP request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- aiohttp: additional methods (CWE-918) ---
		{
			ID:            "py.aiohttp.clientsession.post",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `aiohttp\.ClientSession\s*\(\s*\)\.(post|put|delete|head|patch|request|ws_connect)\s*\(`,
			ObjectType:    "aiohttp.ClientSession",
			MethodName:    "post/put/delete/head/patch/request/ws_connect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "aiohttp client request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- httpx: additional methods (CWE-918) ---
		{
			ID:            "py.httpx.put",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `httpx\.(put|delete|head|options|patch|request)\s*\(`,
			ObjectType:    "httpx",
			MethodName:    "put/delete/head/options/patch/request",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "httpx HTTP request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "py.httpx.client",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `httpx\.Client\s*\(\s*\)\.(get|post|put|delete|head|options|patch|request)\s*\(`,
			ObjectType:    "httpx.Client",
			MethodName:    "Client().get/post/...",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "httpx Client request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "py.httpx.asyncclient.post",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `httpx\.AsyncClient\s*\(\s*\)\.(post|put|delete|head|options|patch|request)\s*\(`,
			ObjectType:    "httpx.AsyncClient",
			MethodName:    "AsyncClient().post/put/...",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "httpx AsyncClient request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			// httpx.stream("GET", url) — streaming request; URL is the 2nd
			// positional arg (after the HTTP method). Common when proxying or
			// downloading a user-supplied URL. Not covered by the get/post/...
			// verb entries above, which only match the named request methods.
			ID:            "py.httpx.stream",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `httpx\.stream\s*\(`,
			ObjectType:    "httpx",
			MethodName:    "stream",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "httpx streaming request with potentially tainted URL (SSRF) — URL is 2nd arg after method",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			// httpx.Client().stream("GET", url) — streaming request on a sync client.
			ID:            "py.httpx.client.stream",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `httpx\.Client\s*\(\s*\)\.stream\s*\(`,
			ObjectType:    "httpx.Client",
			MethodName:    "stream",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "httpx Client streaming request with potentially tainted URL (SSRF) — URL is 2nd arg after method",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			// httpx.AsyncClient().stream("GET", url) — streaming request on an async client.
			ID:            "py.httpx.asyncclient.stream",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `httpx\.AsyncClient\s*\(\s*\)\.stream\s*\(`,
			ObjectType:    "httpx.AsyncClient",
			MethodName:    "stream",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "httpx AsyncClient streaming request with potentially tainted URL (SSRF) — URL is 2nd arg after method",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- http.client stdlib (CWE-918) ---
		{
			ID:            "py.http.client.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `http\.client\.HTTPConnection\s*\(|http\.client\.HTTPSConnection\s*\(|HTTPConnection\s*\([^)]*\)\.request\s*\(|HTTPSConnection\s*\([^)]*\)\.request\s*\(`,
			ObjectType:    "http.client",
			MethodName:    "HTTPConnection/HTTPSConnection",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "stdlib http.client request with potentially tainted host/URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- httplib2 (CWE-918) ---
		{
			ID:            "py.httplib2.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `httplib2\.Http\s*\(.*\.request\s*\(`,
			ObjectType:    "httplib2.Http",
			MethodName:    "Http().request",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "httplib2 HTTP request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- treq / Twisted (CWE-918) ---
		{
			ID:            "py.treq.get",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `treq\.(get|post|put|delete|head|request)\s*\(`,
			ObjectType:    "treq",
			MethodName:    "treq.get/post/...",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Twisted treq HTTP request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- pycurl (CWE-918) ---
		{
			ID:            "py.pycurl.setopt.url",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `\.setopt\s*\(\s*pycurl\.URL\s*,`,
			ObjectType:    "pycurl.Curl",
			MethodName:    "Curl.setopt",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "pycurl URL set with potentially tainted value (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- ftplib SSRF + cleartext FTP (CWE-918 / CWE-319) ---
		// Coverage gap (cov/python): ftplib is the stdlib FTP client; the
		// constructor host argument and the .connect() host argument are an
		// SSRF + credential-exfil vector when built from request data.
		// Module-qualified `ftplib.FTP(`/`ftplib.FTP_TLS(` — ftplib is a
		// single-purpose network module so the name is unambiguous; there is
		// no bare-name fallback. The taint engine still requires the host to
		// be user-derived, so a constant-host FTP target produces no finding.
		{
			ID:            "py.ftplib.ftp.constructor",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `ftplib\.FTP(?:_TLS)?\s*\(`,
			ObjectType:    "ftplib.FTP",
			MethodName:    "ftplib.FTP/FTP_TLS",
			Module:        "ftplib",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ftplib.FTP/FTP_TLS connection to a potentially tainted host (SSRF / cleartext FTP)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			// ftp.connect(host, ...) on an ftplib.FTP instance — the host is a
			// distinct SSRF entrypoint from the constructor (code that does
			// `ftp = ftplib.FTP(); ftp.connect(host)`). Receiver anchored to
			// the ftplib.FTP ObjectType (conventionally bound to `ftp`/`ftps`).
			ID:            "py.ftplib.ftp.connect",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `\bftp(?:s)?\.connect\s*\(`,
			ObjectType:    "ftplib.FTP",
			MethodName:    "connect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ftplib FTP.connect() to a potentially tainted host (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- xmlrpc.client.ServerProxy SSRF (CWE-918) ---
		// Coverage gap (cov/python): Batou already models xmlrpc.client.loads
		// as a CWE-502 deserialization sink, but ServerProxy(url) — which sets
		// the remote XML-RPC endpoint — is an SSRF sink (the only argument is a
		// URL). Module-qualified (Module+RequireModule) so it cannot match any
		// other ServerProxy class. The Py3 `xmlrpc.client` and Py2 `xmlrpclib`
		// modules bind to different receiver names, so they get separate
		// entries with the correct per-module gate.
		{
			ID:            "py.xmlrpc.client.serverproxy",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `xmlrpc\.client\.ServerProxy\s*\(`,
			ObjectType:    "xmlrpc.client",
			MethodName:    "ServerProxy",
			Module:        "xmlrpc",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "xmlrpc.client.ServerProxy with potentially tainted endpoint URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "py.xmlrpclib.serverproxy",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `xmlrpclib\.ServerProxy\s*\(|xmlrpclib\.Server\s*\(`,
			ObjectType:    "xmlrpclib",
			MethodName:    "ServerProxy/Server",
			Module:        "xmlrpclib",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "xmlrpclib.ServerProxy (Python 2) with potentially tainted endpoint URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- telnetlib SSRF + cleartext (CWE-918 / CWE-319) ---
		// telnetlib.Telnet(host, port) is a single-purpose stdlib network
		// client; a request-derived host is an SSRF/cleartext-protocol vector.
		// Module-qualified, no bare fallback.
		{
			ID:            "py.telnetlib.telnet",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `telnetlib\.Telnet\s*\(`,
			ObjectType:    "telnetlib.Telnet",
			MethodName:    "telnetlib.Telnet",
			Module:        "telnetlib",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "telnetlib.Telnet connection to a potentially tainted host (SSRF / cleartext protocol)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- smtplib SMTP / IMAP / POP host SSRF (CWE-918) ---
		// Distinct from the existing py.smtplib.sendmail (CWE-93 header-
		// injection) sink: the SMTP/SMTP_SSL/IMAP4/POP3 *constructor* host
		// argument is an SSRF entrypoint when built from request data (an
		// attacker steers the mail/IMAP server the app connects to). Each
		// protocol has a distinct constructor name, so the structural matcher
		// (which matches a constructor call when the call name equals the
		// ObjectType's last component) needs one entry per protocol with the
		// ObjectType naming that exact constructor. Module-qualified.
		{
			ID:            "py.smtplib.smtp.host",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `smtplib\.SMTP(?:_SSL)?\s*\(`,
			ObjectType:    "smtplib.SMTP",
			MethodName:    "smtplib.SMTP/SMTP_SSL",
			Module:        "smtplib",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "smtplib SMTP client connecting to a potentially tainted host (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "py.imaplib.imap4.host",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `imaplib\.IMAP4(?:_SSL)?\s*\(`,
			ObjectType:    "imaplib.IMAP4",
			MethodName:    "imaplib.IMAP4/IMAP4_SSL",
			Module:        "imaplib",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "imaplib IMAP4 client connecting to a potentially tainted host (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "py.poplib.pop3.host",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `poplib\.POP3(?:_SSL)?\s*\(`,
			ObjectType:    "poplib.POP3",
			MethodName:    "poplib.POP3/POP3_SSL",
			Module:        "poplib",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "poplib POP3 client connecting to a potentially tainted host (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- jinja2 Environment template-name traversal (CWE-22) ---
		// Coverage gap (cov/python): distinct from the existing
		// py.jinja2.from_string SSTI sink. When the *template name* passed to
		// Environment.get_template()/select_template()/get_or_select_template()
		// is attacker-controlled, the loader resolves an arbitrary template
		// path on disk (path traversal / unintended template disclosure or
		// execution). Receiver anchored to the jinja2.Environment ObjectType
		// (conventionally bound to `env`/`jinja_env`/`environment`).
		{
			ID:            "py.jinja2.environment.get_template",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `\.(get_template|select_template|get_or_select_template)\s*\(`,
			ObjectType:    "jinja2.Environment",
			MethodName:    "get_template/select_template/get_or_select_template",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "jinja2 Environment.get_template() with a potentially tainted template name (template-path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Django JsonResponse XSS (CWE-79) ---
		{
			ID:            "py.django.jsonresponse",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `JsonResponse\(`,
			ObjectType:    "django.http",
			MethodName:    "JsonResponse",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Django JsonResponse with potentially tainted data",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Django Header injection via StreamingHttpResponse (CWE-113) ---
		{
			ID:            "py.django.streaminghttpresponse",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `StreamingHttpResponse\(`,
			ObjectType:    "django.http",
			MethodName:    "StreamingHttpResponse",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Django StreamingHttpResponse with potentially tainted streaming content",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- hashlib with user-controlled key (CWE-328) ---
		{
			ID:            "py.hashlib.new",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `hashlib\.new\(`,
			ObjectType:    "hashlib",
			MethodName:    "new",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Dynamic hash algorithm selection with potentially tainted algorithm name",
			CWEID:         "CWE-328",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// --- Mako template injection (CWE-1336) ---
		{
			ID:            "py.mako.template",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `mako\.template\.Template\(|Template\(.*text\s*=`,
			ObjectType:    "mako.template",
			MethodName:    "Template",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Mako template with user-controlled template string (SSTI)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Chameleon SSTI (CWE-1336) ---
		{
			ID:            "py.chameleon.pagetemplate",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `\bPageTemplate\s*\(`,
			ObjectType:    "chameleon.PageTemplate",
			MethodName:    "PageTemplate",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Chameleon PageTemplate with user-controlled template source (SSTI → RCE via TALES)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.chameleon.pagetemplatestring",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `\bPageTemplateString\s*\(`,
			ObjectType:    "chameleon.PageTemplateString",
			MethodName:    "PageTemplateString",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Chameleon PageTemplateString with user-controlled template source (SSTI → RCE via TALES)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Cheetah3 SSTI (CWE-1336) ---
		{
			ID:            "py.cheetah.template",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `Cheetah\.Template\.Template\s*\(`,
			ObjectType:    "Cheetah.Template",
			MethodName:    "Template",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Cheetah Template with user-controlled source (SSTI → RCE via #python/$eval directives)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Tornado template SSTI (CWE-1336) ---
		{
			ID:            "py.tornado.template",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `tornado\.template\.Template\s*\(`,
			ObjectType:    "tornado.template",
			MethodName:    "Template",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Tornado Template with user-controlled template source (SSTI → RCE via {% %} expressions)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Genshi SSTI (CWE-1336) ---
		{
			ID:            "py.genshi.markuptemplate",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `\bMarkupTemplate\s*\(`,
			ObjectType:    "genshi.template.MarkupTemplate",
			MethodName:    "MarkupTemplate",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Genshi MarkupTemplate with user-controlled XML source (SSTI → attribute disclosure)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.genshi.texttemplate",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `\bTextTemplate\s*\(`,
			ObjectType:    "genshi.template.TextTemplate",
			MethodName:    "TextTemplate",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Genshi TextTemplate with user-controlled template source (SSTI → attribute disclosure)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Bottle SimpleTemplate SSTI (CWE-1336) ---
		{
			ID:            "py.bottle.simpletemplate",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `\bSimpleTemplate\s*\(`,
			ObjectType:    "bottle.SimpleTemplate",
			MethodName:    "SimpleTemplate",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Bottle SimpleTemplate with user-controlled source (SSTI → RCE via embedded Python)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Django cursor.execute (CWE-89) ---
		{
			ID:            "py.django.cursor.execute",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `cursor\.execute\(`,
			ObjectType:    "django.db.connection",
			MethodName:    "cursor.execute",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Django raw cursor.execute with potentially tainted SQL",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- XPath Injection (CWE-643) ---
		{
			ID:            "py.lxml.etree.xpath",
			Category:      taint.SnkXPath,
			Language:      rules.LangPython,
			Pattern:       `lxml\.etree\.XPath\(|\.xpath\(`,
			ObjectType:    "",
			MethodName:    "XPath/xpath",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "lxml XPath evaluation with potentially tainted expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.xml.etree.findall",
			Category:      taint.SnkXPath,
			Language:      rules.LangPython,
			Pattern:       `\.findall\s*\(`,
			ObjectType:    "xml.etree.ElementTree",
			MethodName:    "findall",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ElementTree findall with potentially tainted XPath pattern",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.xml.etree.find",
			Category:      taint.SnkXPath,
			Language:      rules.LangPython,
			Pattern:       `\.find\s*\(`,
			ObjectType:    "xml.etree.ElementTree",
			MethodName:    "find",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ElementTree find with potentially tainted XPath pattern",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.elementpath.select",
			Category:      taint.SnkXPath,
			Language:      rules.LangPython,
			Pattern:       `elementpath\.select\(`,
			ObjectType:    "",
			MethodName:    "elementpath.select/select",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "elementpath XPath evaluation with potentially tainted expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- XSLT Injection (CWE-91) ---
		// Attacker-controlled XSLT stylesheets enable arbitrary file read
		// via the document() function, outbound network access via
		// xsl:include / xsl:import, and — with EXSLT extensions such as
		// exsl:document or dyn:evaluate — command / code execution.
		// See CVE-2025-6985 (langchain-text-splitters passed request-derived
		// XSLT to lxml.etree.XSLT without hardening) and CVE-2019-13117 /
		// CVE-2015-8478 for libxslt-level exploitation of the same class.
		// Mitigation: never compile user-supplied stylesheets, or wrap with
		// lxml.etree.XSLTAccessControl.DENY_ALL plus a no-network XMLParser.
		{
			ID:            "py.lxml.etree.xslt",
			Category:      taint.SnkXPath,
			Language:      rules.LangPython,
			Pattern:       `(?:lxml\.)?etree\.XSLT\s*\(`,
			ObjectType:    "lxml.etree",
			MethodName:    "XSLT",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "lxml.etree.XSLT compiles a tainted stylesheet — attacker controls XSLT body, enabling file read via document(), SSRF via xsl:include, and RCE via EXSLT extensions",
			CWEID:         "CWE-91",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.lxml.isoschematron.schematron",
			Category:      taint.SnkXPath,
			Language:      rules.LangPython,
			Pattern:       `(?:lxml\.)?isoschematron\.Schematron\s*\(`,
			ObjectType:    "lxml.isoschematron",
			MethodName:    "Schematron",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "lxml.isoschematron.Schematron compiles the schema as XSLT under the hood — a tainted schema inherits XSLT-injection semantics (file read, SSRF, EXSLT RCE)",
			CWEID:         "CWE-91",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- pathlib (CWE-22 Path Traversal) ---
		{
			ID:            "py.pathlib.read_text",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `\.read_text\s*\(|\.read_bytes\s*\(`,
			ObjectType:    "",
			MethodName:    "read_text/read_bytes",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "pathlib read with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.pathlib.write_text",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `\.write_text\s*\(|\.write_bytes\s*\(`,
			ObjectType:    "",
			MethodName:    "write_text/write_bytes",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "pathlib write with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.pathlib.open",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `\.open\s*\(`,
			ObjectType:    "Path",
			MethodName:    "open",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "pathlib open with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.pathlib.exists",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `\.exists\s*\(`,
			ObjectType:    "Path",
			MethodName:    "exists",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "pathlib exists check with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- stdlib File Read (CWE-22 Path Traversal) ---
		// NOTE: open(), io.open(), tarfile.open(), aiofiles.open(), send_file(),
		// shutil.copy() all extract method name "open"/"copy" and are already
		// covered by existing SnkFileWrite entries (py.open, py.shutil.copy, etc.)
		{
			ID:            "py.os.listdir",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `os\.listdir\s*\(`,
			ObjectType:    "os",
			MethodName:    "os.listdir",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Directory listing with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.os.scandir",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `os\.scandir\s*\(`,
			ObjectType:    "os",
			MethodName:    "os.scandir",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Directory scanning with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.os.stat",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `os\.(?:stat|lstat)\s*\(`,
			ObjectType:    "os",
			MethodName:    "os.stat/lstat",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "File metadata access with potentially tainted path (info disclosure)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.os.path.exists",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `os\.path\.(?:exists|isfile|isdir|islink)\s*\(`,
			ObjectType:    "os.path",
			MethodName:    "os.path.exists/isfile/isdir/islink",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Path existence check with tainted path (info disclosure via probing)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.glob.glob",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `glob\.(?:glob|iglob)\s*\(`,
			ObjectType:    "glob",
			MethodName:    "glob.glob/iglob",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Directory listing via glob with tainted pattern (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.zipfile.open",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `ZipFile\s*\(`,
			ObjectType:    "zipfile",
			MethodName:    "ZipFile",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Zip file access with tainted path (path traversal / zip slip)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Peewee ORM Raw SQL (CWE-89) ---
		{
			ID:            "py.peewee.rawquery",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `RawQuery\(`,
			ObjectType:    "peewee",
			MethodName:    "RawQuery",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Peewee RawQuery() with potentially tainted raw SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.peewee.sql",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.SQL\(`,
			ObjectType:    "peewee",
			MethodName:    "SQL",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Peewee SQL() raw SQL expression with potentially tainted input",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.peewee.execute_sql",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.execute_sql\(`,
			ObjectType:    "peewee.Database",
			MethodName:    "execute_sql",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Peewee database.execute_sql() with potentially tainted raw SQL",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Tortoise ORM Raw SQL (CWE-89) ---
		{
			ID:            "py.tortoise.rawsql",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `RawSQL\(`,
			ObjectType:    "tortoise",
			MethodName:    "RawSQL",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Tortoise ORM RawSQL() with potentially tainted raw SQL string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.tortoise.executequery",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.execute_query\(`,
			ObjectType:    "tortoise",
			MethodName:    "execute_query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Tortoise ORM execute_query() with potentially tainted raw SQL",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.tortoise.executequerydirect",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `execute_query\(`,
			ObjectType:    "tortoise.connections",
			MethodName:    "execute_query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Tortoise ORM connections execute_query() with potentially tainted raw SQL",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Trust Boundary Violation (CWE-501) ---
		{
			ID:            "py.flask.session.store",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPython,
			Pattern:       `session\[`,
			ObjectType:    "flask.session",
			MethodName:    "[]",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Flask session stores potentially tainted data (trust boundary violation)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "py.django.session.store",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPython,
			Pattern:       `request\.session\[`,
			ObjectType:    "django.session",
			MethodName:    "[]",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Django session stores potentially tainted data (trust boundary violation)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "py.session.update",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPython,
			Pattern:       `session\.update\s*\(`,
			ObjectType:    "session",
			MethodName:    "update",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Session update with potentially tainted data (trust boundary violation)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},

		// --- Task queue trust boundary: enqueueing tainted args (CWE-501) ---
		// Producer-side trust boundary: when a web handler pushes user-controlled
		// values into a task queue, those args are serialized (pickle/JSON) into
		// Redis/RabbitMQ/SQS and later deserialized and executed by a worker in
		// a privileged context. Tainted arg → cross-boundary re-execution.
		// Mirror of the existing Ruby Sidekiq/Resque/ActiveJob sinks and the
		// existing py.celery.task_args *source* (which taints worker-side args).
		{
			ID:            "py.celery.apply_async",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPython,
			Pattern:       `\.apply_async\s*\(`,
			ObjectType:    "",
			MethodName:    "apply_async",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Celery (or multiprocessing.Pool) task enqueue with tainted args — args crosses trust boundary (serialized to broker, re-executed later)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "py.celery.send_task",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPython,
			Pattern:       `\.send_task\s*\(`,
			ObjectType:    "",
			MethodName:    "send_task",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Celery app.send_task() with tainted name or args — crosses trust boundary (serialized to broker, re-executed later)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "py.rq.enqueue",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPython,
			Pattern:       `\.enqueue\s*\(`,
			ObjectType:    "",
			MethodName:    "enqueue",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "RQ queue.enqueue() with tainted args — args pickled to Redis, re-executed later in worker context (trust boundary)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "py.rq.enqueue_in",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPython,
			Pattern:       `\.enqueue_in\s*\(`,
			ObjectType:    "",
			MethodName:    "enqueue_in",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "RQ queue.enqueue_in() scheduled job with tainted args — crosses trust boundary via Redis",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "py.rq.enqueue_at",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPython,
			Pattern:       `\.enqueue_at\s*\(`,
			ObjectType:    "",
			MethodName:    "enqueue_at",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "RQ queue.enqueue_at() scheduled job with tainted args — crosses trust boundary via Redis",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "py.dramatiq.send_with_options",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPython,
			Pattern:       `\.send_with_options\s*\(`,
			ObjectType:    "",
			MethodName:    "send_with_options",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Dramatiq actor.send_with_options() with tainted args/kwargs — crosses trust boundary (broker → worker)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "py.arq.enqueue_job",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPython,
			Pattern:       `\.enqueue_job\s*\(`,
			ObjectType:    "",
			MethodName:    "enqueue_job",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "arq redis.enqueue_job() with tainted args — args serialized to Redis, re-executed in worker (trust boundary)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},

		// --- Open Redirect (CWE-601) ---
		{
			ID:            "py.django.httpresponseredirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangPython,
			Pattern:       `HttpResponseRedirect\s*\(`,
			ObjectType:    "django.http.HttpResponseRedirect",
			MethodName:    "HttpResponseRedirect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Django HttpResponseRedirect with potentially tainted URL",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.django.httpresponsepermanentredirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangPython,
			Pattern:       `HttpResponsePermanentRedirect\s*\(`,
			ObjectType:    "django.http.HttpResponsePermanentRedirect",
			MethodName:    "HttpResponsePermanentRedirect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Django HttpResponsePermanentRedirect with potentially tainted URL",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.fastapi.redirectresponse",
			Category:      taint.SnkRedirect,
			Language:      rules.LangPython,
			Pattern:       `RedirectResponse\s*\(`,
			ObjectType:    "fastapi.responses.RedirectResponse",
			MethodName:    "RedirectResponse",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "FastAPI/Starlette RedirectResponse with potentially tainted URL",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.pyramid.httpfound",
			Category:      taint.SnkRedirect,
			Language:      rules.LangPython,
			Pattern:       `HTTPFound\s*\(`,
			ObjectType:    "pyramid.httpexceptions.HTTPFound",
			MethodName:    "HTTPFound",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Pyramid HTTPFound redirect with potentially tainted location",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.tornado.redirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangPython,
			Pattern:       `self\.redirect\s*\(`,
			ObjectType:    "",
			MethodName:    "redirect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Tornado redirect with potentially tainted URL",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- HTTP Header Injection (CWE-113) ---
		{
			ID:            "py.tornado.set_header",
			Category:      taint.SnkHeader,
			Language:      rules.LangPython,
			Pattern:       `self\.set_header\s*\(`,
			ObjectType:    "",
			MethodName:    "set_header",
			DangerousArgs: []int{1},
			Severity:      rules.Medium,
			Description:   "Tornado set_header with potentially tainted value",
			CWEID:         "CWE-113",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.tornado.add_header",
			Category:      taint.SnkHeader,
			Language:      rules.LangPython,
			Pattern:       `self\.add_header\s*\(`,
			ObjectType:    "",
			MethodName:    "add_header",
			DangerousArgs: []int{1},
			Severity:      rules.Medium,
			Description:   "Tornado add_header with potentially tainted value",
			CWEID:         "CWE-113",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.wsgi.start_response",
			Category:      taint.SnkHeader,
			Language:      rules.LangPython,
			Pattern:       `start_response\s*\(`,
			ObjectType:    "",
			MethodName:    "start_response",
			DangerousArgs: []int{1},
			Severity:      rules.Medium,
			Description:   "WSGI start_response with potentially tainted headers",
			CWEID:         "CWE-113",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- NoSQL Injection / MongoDB (CWE-943) ---
		{
			ID:            "py.pymongo.find_one",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.find_one\s*\(`,
			ObjectType:    "",
			MethodName:    "find_one",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PyMongo find_one with user-controlled query (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		// db.eval / Database.eval ran arbitrary server-side JavaScript on
		// the mongod (removed in MongoDB 4.2 but live on legacy clusters
		// and still a sink in pymongo<4). A tainted body is direct RCE on
		// the database server. Anchor to the `.eval(` method on a db-like
		// receiver to avoid colliding with ast.literal_eval / template
		// `.eval()` helpers.
		{
			ID:            "py.pymongo.eval",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\b(?:db|database|mongo|conn|connection|client)\.eval\s*\(`,
			ObjectType:    "database",
			MethodName:    "eval",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MongoDB db.eval() executes attacker-controlled JavaScript server-side (RCE on the database host). Never pass tainted code; db.eval is deprecated — use parameterized queries.",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pymongo.find_one_and_update",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.find_one_and_update\s*\(`,
			ObjectType:    "",
			MethodName:    "find_one_and_update",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PyMongo find_one_and_update with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pymongo.find_one_and_replace",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.find_one_and_replace\s*\(`,
			ObjectType:    "",
			MethodName:    "find_one_and_replace",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PyMongo find_one_and_replace with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pymongo.find_one_and_delete",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.find_one_and_delete\s*\(`,
			ObjectType:    "",
			MethodName:    "find_one_and_delete",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PyMongo find_one_and_delete with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pymongo.update_one",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.update_one\s*\(`,
			ObjectType:    "",
			MethodName:    "update_one",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PyMongo update_one with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pymongo.update_many",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.update_many\s*\(`,
			ObjectType:    "",
			MethodName:    "update_many",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PyMongo update_many with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pymongo.delete_one",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.delete_one\s*\(`,
			ObjectType:    "",
			MethodName:    "delete_one",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PyMongo delete_one with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pymongo.delete_many",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.delete_many\s*\(`,
			ObjectType:    "",
			MethodName:    "delete_many",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PyMongo delete_many with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pymongo.replace_one",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.replace_one\s*\(`,
			ObjectType:    "",
			MethodName:    "replace_one",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PyMongo replace_one with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pymongo.count_documents",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.count_documents\s*\(`,
			ObjectType:    "",
			MethodName:    "count_documents",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "PyMongo count_documents with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pymongo.aggregate",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.aggregate\s*\(`,
			ObjectType:    "",
			MethodName:    "aggregate",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "PyMongo aggregate with user-controlled pipeline (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pymongo.distinct",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.distinct\s*\(`,
			ObjectType:    "",
			MethodName:    "distinct",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "PyMongo distinct with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pymongo.insert_one",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.insert_one\s*\(`,
			ObjectType:    "",
			MethodName:    "insert_one",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "PyMongo insert_one with user-controlled document (operator injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pymongo.insert_many",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.insert_many\s*\(`,
			ObjectType:    "",
			MethodName:    "insert_many",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "PyMongo insert_many with user-controlled documents (operator injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- CSV / spreadsheet formula injection (CWE-1236) ---
		// A cell value beginning with =, +, -, @, tab or CR is interpreted as
		// a formula by Excel / LibreOffice / Google Sheets when the exported
		// file is opened, enabling DDE / command execution on the viewer's
		// machine. The dangerous arg is the row/field data being written.
		// `writerow`/`writerows`/`to_csv` are distinctive enough not to need
		// module binding (mirrors the bare-name pymongo sinks above). One
		// entry per method name covers both csv.writer and csv.DictWriter.
		{
			ID:            "py.csv.writer.writerow",
			Category:      taint.SnkCSV,
			Language:      rules.LangPython,
			Pattern:       `\.writerow\s*\(`,
			ObjectType:    "",
			MethodName:    "writerow",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "csv.writer/csv.DictWriter .writerow() with user-controlled row — values beginning with =, +, -, @ become formulas when the CSV is opened in a spreadsheet (CSV/formula injection)",
			CWEID:         "CWE-1236",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.csv.writer.writerows",
			Category:      taint.SnkCSV,
			Language:      rules.LangPython,
			Pattern:       `\.writerows\s*\(`,
			ObjectType:    "",
			MethodName:    "writerows",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "csv.writer/csv.DictWriter .writerows() with user-controlled rows — values beginning with =, +, -, @ become formulas when the CSV is opened in a spreadsheet (CSV/formula injection)",
			CWEID:         "CWE-1236",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pandas.to_csv",
			Category:      taint.SnkCSV,
			Language:      rules.LangPython,
			Pattern:       `\.to_csv\s*\(`,
			ObjectType:    "pandas.DataFrame",
			MethodName:    "to_csv",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "pandas DataFrame.to_csv() — when the DataFrame holds user-controlled cell values, exported strings beginning with =, +, -, @ become formulas when the CSV is opened in a spreadsheet (CSV/formula injection)",
			CWEID:         "CWE-1236",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Unrestricted file upload (CWE-434) ---
		// An uploaded file persisted to disk without validating its
		// extension / MIME type / content lets an attacker drop a webshell
		// or otherwise smuggle executable content. The sink is the persist
		// call; either the uploaded-file handle (the receiver) or the
		// destination path being tainted produces a flow. `save` is bound
		// to FileStorage / Storage receivers so unrelated `.save()` calls
		// (Django models, PIL images) don't match; `copyfileobj` is bound
		// to the `shutil` module.
		{
			ID:            "py.werkzeug.filestorage.save",
			Category:      taint.SnkUpload,
			Language:      rules.LangPython,
			Pattern:       `\.save\s*\(`,
			ObjectType:    "FileStorage",
			MethodName:    "save",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Werkzeug/Flask FileStorage.save() persisting a request.files[...] upload without extension/MIME validation (unrestricted file upload)",
			CWEID:         "CWE-434",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "py.django.storage.save",
			Category:      taint.SnkUpload,
			Language:      rules.LangPython,
			Pattern:       `\.save\s*\(`,
			ObjectType:    "Storage",
			MethodName:    "save",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Django FileSystemStorage/default_storage.save() persisting an uploaded file (request.FILES) without extension/MIME validation (unrestricted file upload)",
			CWEID:         "CWE-434",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "py.shutil.copyfileobj",
			Category:      taint.SnkUpload,
			Language:      rules.LangPython,
			Pattern:       `shutil\.copyfileobj\s*\(`,
			ObjectType:    "",
			MethodName:    "copyfileobj",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "shutil.copyfileobj() copying a FastAPI UploadFile.file (or other uploaded-file handle) to a destination without extension/MIME validation (unrestricted file upload)",
			CWEID:         "CWE-434",
			OWASPCategory: "A04:2021-Insecure Design",
			Module:        "shutil",
			RequireModule: true,
		},

		// --- Starlette/FastAPI Response Sinks (CWE-79, CWE-22) ---
		{
			ID:            "py.starlette.htmlresponse",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `HTMLResponse\s*\(`,
			ObjectType:    "starlette.responses.HTMLResponse",
			MethodName:    "HTMLResponse",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Starlette/FastAPI HTMLResponse with potentially tainted HTML content (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		// PlainTextResponse renders its body with a text/plain content-type, but
		// browsers will sniff or a caller may override the header, and reflected
		// markup in an error/debug page is still a real XSS vector. Anchored to
		// the starlette.responses.PlainTextResponse receiver type (distinct from
		// HTMLResponse above) so it never collides with an unrelated
		// PlainTextResponse symbol.
		{
			ID:            "py.starlette.plaintextresponse",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `PlainTextResponse\s*\(`,
			ObjectType:    "starlette.responses.PlainTextResponse",
			MethodName:    "PlainTextResponse",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Starlette/FastAPI PlainTextResponse with potentially tainted body — reflected content in a response page (XSS/HTML-injection if the content-type is overridden or sniffed)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.starlette.fileresponse",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `FileResponse\s*\(`,
			ObjectType:    "starlette.responses.FileResponse",
			MethodName:    "FileResponse",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Starlette/FastAPI FileResponse with potentially tainted file path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.starlette.streamingresponse",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `StreamingResponse\s*\(`,
			ObjectType:    "starlette.responses.StreamingResponse",
			MethodName:    "StreamingResponse",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Starlette/FastAPI StreamingResponse with potentially tainted content",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.fastapi.templateresponse",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `TemplateResponse\s*\(`,
			ObjectType:    "fastapi.templating.Jinja2Templates",
			MethodName:    "TemplateResponse",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "FastAPI Jinja2Templates.TemplateResponse with potentially tainted template name (template injection / path traversal). The template name is positional arg 0 in legacy style or arg 1 in the new (request, name, context) style.",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.fastapi.jinja2templates.directory",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `Jinja2Templates\s*\(`,
			ObjectType:    "fastapi.templating.Jinja2Templates",
			MethodName:    "Jinja2Templates",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "FastAPI Jinja2Templates initialised with a tainted directory path — attacker can redirect template loader to arbitrary filesystem paths.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.fastapi.websocket.send_text",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `\.send_text\s*\(`,
			ObjectType:    "fastapi.WebSocket",
			MethodName:    "send_text",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "FastAPI WebSocket.send_text echoing tainted data to the client. If the frontend renders this as HTML, the WebSocket channel becomes an XSS vector.",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.fastapi.websocket.send_json",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `\.send_json\s*\(`,
			ObjectType:    "fastapi.WebSocket",
			MethodName:    "send_json",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "FastAPI WebSocket.send_json echoing tainted data to the client. Sensitive data exposure or XSS if the frontend renders fields as HTML.",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- aiohttp Web Response Sinks (CWE-79) ---
		// Receiver-scoping note (PR-CAT2py): with ObjectType
		// "aiohttp.web.Response", the matcher's constructor-pattern
		// fallback (extractCallReceiver == "" branch) matched bare
		// `Response(data)` from `rest_framework.response.Response` and any
		// other framework Response class. The Sentry triage attributed
		// ~6/80 cross-file XSS findings to DRF Response collisions alone.
		// We pin the sink to the aiohttp module via Module + RequireModule
		// so it only fires on `web.Response(...)` / `aiohttp.web.Response`
		// — DRF's `Response` is JSON-by-default and is not an HTML sink.
		{
			ID:            "py.aiohttp.web.response",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `\b(?:aiohttp\.web|web)\.Response\s*\(`,
			ObjectType:    "aiohttp.web.Response",
			MethodName:    "web.Response",
			Module:        "web",
			RequireModule: true,
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "aiohttp web.Response with potentially tainted body/text (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Sanic response XSS sinks (CWE-79) ---
		// Sanic's `from sanic import response` helpers build the HTTP body
		// directly: `response.html(markup)` emits text/html and `response.raw(
		// data)` emits an arbitrary content-type with no escaping. A tainted
		// first argument is reflected verbatim → reflected XSS. We already model
		// the matching Sanic request *sources* (py.sanic.request.*); these are
		// the missing sink half. Anchored to the `response`/`resp` receiver with
		// the Sanic-distinctive `html`/`raw` builder method — `response.json(...)`
		// (auto-escaped JSON) and `response.text(..., content_type=...)` plain
		// text are deliberately NOT modeled as HTML sinks here.
		{
			ID:            "py.sanic.response.html",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `(?:sanic\.)?response\.html\s*\(`,
			ObjectType:    "sanic.response",
			MethodName:    "html",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Sanic response.html() with potentially tainted markup — reflected content rendered as text/html (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.sanic.response.raw",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangPython,
			Pattern:       `(?:sanic\.)?response\.raw\s*\(`,
			ObjectType:    "sanic.response",
			MethodName:    "raw",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Sanic response.raw() with potentially tainted bytes and a caller-controlled content-type — reflected body can be sniffed/served as HTML (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Archive Extraction Sinks (CWE-22, CVE-2007-4559) ---
		{
			ID:            "py.archive.extractall",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `\.extractall\s*\(`,
			ObjectType:    "",
			MethodName:    "extractall",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Archive extractall() with tainted path — zip-slip/tar-slip path traversal (CVE-2007-4559)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.shutil.unpack_archive",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `shutil\.unpack_archive\s*\(`,
			ObjectType:    "shutil",
			MethodName:    "unpack_archive",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "shutil.unpack_archive() with tainted archive path or extract directory (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- asyncpg (async PostgreSQL driver) — Connection SQL Injection (CWE-89) ---
		{
			ID:            "py.asyncpg.execute",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `conn\.execute\s*\(|conn\.executemany\s*\(`,
			ObjectType:    "asyncpg.Connection",
			MethodName:    "execute/executemany",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "asyncpg Connection execute()/executemany() with tainted raw SQL — use $1, $2 placeholders",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.asyncpg.fetchquery",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `conn\.fetch\s*\(|conn\.fetchrow\s*\(|conn\.fetchval\s*\(|conn\.fetchmany\s*\(`,
			ObjectType:    "asyncpg.Connection",
			MethodName:    "fetch/fetchrow/fetchval/fetchmany",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "asyncpg Connection fetch/fetchrow/fetchval with tainted raw SQL query string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.asyncpg.cursor",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `conn\.cursor\s*\(`,
			ObjectType:    "asyncpg.Connection",
			MethodName:    "cursor",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "asyncpg Connection.cursor() with tainted raw SQL — unlike DB-API cursor(), asyncpg.cursor() takes the query string as arg 0",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- asyncpg — Pool SQL Injection (CWE-89) ---
		// Pool offers the same query API as Connection directly (without needing acquire()).
		{
			ID:            "py.asyncpg.pool.execute",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `pool\.execute\s*\(|pool\.executemany\s*\(`,
			ObjectType:    "asyncpg.Pool",
			MethodName:    "execute/executemany",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "asyncpg Pool execute()/executemany() with tainted raw SQL — use $1, $2 placeholders",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.asyncpg.pool.fetchquery",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `pool\.fetch\s*\(|pool\.fetchrow\s*\(|pool\.fetchval\s*\(|pool\.fetchmany\s*\(`,
			ObjectType:    "asyncpg.Pool",
			MethodName:    "fetch/fetchrow/fetchval/fetchmany",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "asyncpg Pool fetch/fetchrow/fetchval with tainted raw SQL query string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- aiosqlite (async SQLite driver) SQL Injection (CWE-89) ---
		{
			ID:            "py.aiosqlite.execute",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\bdb\.execute\s*\(|\bdb\.executemany\s*\(|aiosqlite\.connect[^)]*\)[^.]*\.execute\s*\(`,
			ObjectType:    "aiosqlite.Connection",
			MethodName:    "execute/executemany",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "aiosqlite Connection execute()/executemany() with tainted SQL — use ? placeholders + params tuple",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.aiosqlite.executescript",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.executescript\s*\(`,
			ObjectType:    "aiosqlite.Connection",
			MethodName:    "executescript",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "aiosqlite executescript() with tainted multi-statement SQL — no parameterization; stacked-statement injection risk",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- databases (encode/databases async ORM wrapper) SQL Injection (CWE-89) ---
		{
			ID:            "py.databases.execute",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `database\.execute\s*\(|database\.execute_many\s*\(|database\.iterate\s*\(`,
			ObjectType:    "databases.Database",
			MethodName:    "execute/execute_many/iterate",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "encode/databases Database execute()/execute_many()/iterate() with tainted raw SQL — bind values via :name placeholders",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.databases.fetch",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `database\.fetch_all\s*\(|database\.fetch_one\s*\(|database\.fetch_val\s*\(`,
			ObjectType:    "databases.Database",
			MethodName:    "fetch_all/fetch_one/fetch_val",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "encode/databases Database fetch_all/fetch_one/fetch_val with tainted raw SQL query string",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- elasticsearch-py / AsyncElasticsearch ES-specific method sinks ---
		// Only method names that are unique enough to Elasticsearch (so ObjectType=""
		// does not cause false positives on stdlib / pandas / ORMs). Generic names
		// like search/update/count/reindex are intentionally excluded — the regex
		// layer (BATOU-NOSQL-*) already covers the common query_string / Lucene
		// DSL patterns for those methods.
		{
			ID:            "py.elasticsearch.msearch",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.msearch\s*\(`,
			ObjectType:    "",
			MethodName:    "msearch",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Elasticsearch client msearch() (multi-search) with tainted NDJSON body — query-DSL injection bypasses filters (CWE-943)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.elasticsearch.delete_by_query",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.delete_by_query\s*\(`,
			ObjectType:    "",
			MethodName:    "delete_by_query",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch delete_by_query() with tainted query — DSL injection can delete documents outside the intended scope (CWE-943)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.elasticsearch.update_by_query",
			Category:      taint.SnkEval,
			Language:      rules.LangPython,
			Pattern:       `\.update_by_query\s*\(`,
			ObjectType:    "",
			MethodName:    "update_by_query",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch update_by_query() with tainted body — Painless script field allows arbitrary code execution; query field allows DSL injection (CWE-94/CWE-943)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- elasticsearch-py Painless / stored script execution (CWE-94) ---
		{
			ID:            "py.elasticsearch.scripts_painless_execute",
			Category:      taint.SnkEval,
			Language:      rules.LangPython,
			Pattern:       `\.scripts_painless_execute\s*\(`,
			ObjectType:    "",
			MethodName:    "scripts_painless_execute",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch scripts_painless_execute() with tainted script body — direct Painless code execution (CWE-94)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.elasticsearch.put_script",
			Category:      taint.SnkEval,
			Language:      rules.LangPython,
			Pattern:       `\.put_script\s*\(`,
			ObjectType:    "",
			MethodName:    "put_script",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch put_script() stores a tainted stored script — later invocations execute attacker-supplied Painless code (CWE-94)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- elasticsearch-py Elasticsearch SQL endpoint (CWE-89) ---
		// PR-CAT6py fix B2: the prior pattern `\.sql\.query\s*\(|sql_query\s*\(`
		// matched the bare `sql_query(` substring, which collided with
		// search-query parser functions like `parse_sql_query(...)` (a
		// Parsimonious grammar parser, not a database executor). The
		// elasticsearch-py client always invokes this as a method on a
		// client object, so requiring a dot-receiver prefix
		// (`.sql.query(` or `.sql_query(`) eliminates the parser-name
		// collision without losing the genuine ES SQL endpoint shape.
		{
			ID:            "py.elasticsearch.sql.query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.sql\.query\s*\(|\.sql_query\s*\(`,
			ObjectType:    "",
			MethodName:    "sql.query/sql_query",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch SQL endpoint (sql.query) with tainted SQL string — classic SQL injection against the ES SQL translator (CWE-89)",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- elasticsearch-py low-level transport (raw HTTP) (CWE-943) ---
		{
			ID:            "py.elasticsearch.transport.perform_request",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.perform_request\s*\(`,
			ObjectType:    "",
			MethodName:    "perform_request",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Elasticsearch low-level Transport.perform_request() with tainted path or body — attackers control the HTTP path, method, and request body (CWE-943)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Neo4j Cypher injection (CWE-943) ---
		// Neo4j's official Python driver (neo4j-python-driver), py2neo, and
		// neomodel execute Cypher queries. Building a Cypher string via
		// concatenation or f-string interpolation from user input allows Cypher
		// injection (attacker can alter MATCH/CREATE/DELETE semantics or chain
		// new clauses). Safe code passes values as keyword args or a parameters
		// dict — e.g. driver.execute_query("MATCH (n) WHERE n.name = $name RETURN n", name=user).
		// See https://neo4j.com/developer/kb/protecting-against-cypher-injection/
		// Note: session.run / tx.run / graph.run are NOT added here because the
		// bare method name "run" collides with py.subprocess.call's broad match
		// pattern and would be mis-classified as OS-command execution. The three
		// sinks below use Neo4j-unique method names and dispatch cleanly.
		{
			ID:            "py.neo4j.driver.execute_query",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `(?:driver|neo4j_driver|async_driver)\.execute_query\s*\(`,
			ObjectType:    "",
			MethodName:    "execute_query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Neo4j Driver.execute_query() (v5+ unified API) with tainted Cypher string (Cypher injection); pass user values via keyword args or a parameters_={} dict instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.py2neo.graph.evaluate",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `(?:graph|py2neo_graph)\.evaluate\s*\(`,
			ObjectType:    "",
			MethodName:    "evaluate",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "py2neo Graph.evaluate() with tainted Cypher string (Cypher injection); pass parameters as a dict argument instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.neomodel.db.cypher_query",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `(?:db|neo_db|neomodel_db)\.cypher_query\s*\(`,
			ObjectType:    "",
			MethodName:    "cypher_query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "neomodel db.cypher_query() with tainted Cypher string (Cypher injection); pass user values via params={} kwarg instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Apache Cassandra / ScyllaDB / DataStax / Astra DB CQL injection (CWE-943) ---
		// DataStax cassandra-driver is the canonical Python client for Cassandra
		// 3.x/4.x and is also used directly against ScyllaDB (wire-compatible),
		// DSE, and Astra DB. CQL is Cassandra's SQL-like query language: building
		// a CQL string by concatenation/f-string and passing it to the driver
		// allows server-side query injection — the safe pattern is a literal
		// CQL with `?` placeholders and a separate `parameters` tuple/list.
		//
		// `Session.execute(...)` is intentionally NOT added here — the bare
		// `\.execute\(` regex would collide with the existing `py.cursor.execute`
		// entry (DB-API/SQLAlchemy/etc) and tightening to ObjectType: "Session"
		// would miss chained forms like `cluster.connect().execute(...)`. The
		// async/concurrent variants below have unique names with no such overlap.
		{
			ID:            "py.cassandra.simplestatement",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\bSimpleStatement\s*\(`,
			ObjectType:    "",
			MethodName:    "SimpleStatement",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DataStax cassandra.query.SimpleStatement(cql) seeded from a tainted CQL string is injectable; use a literal CQL with ? placeholders and a parameters tuple",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.cassandra.session.execute_async",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\.execute_async\s*\(`,
			ObjectType:    "",
			MethodName:    "execute_async",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DataStax cassandra-driver Session.execute_async() with tainted CQL string enables CQL injection; use ? placeholders and pass values via parameters=",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.cassandra.execute_concurrent",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\bexecute_concurrent\s*\(`,
			ObjectType:    "",
			MethodName:    "execute_concurrent",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "DataStax cassandra.concurrent.execute_concurrent(session, statements_and_parameters) with tainted CQL in any statement enables CQL injection; build the statement list from prepared statements or literal CQL with placeholders",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.cassandra.execute_concurrent_with_args",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangPython,
			Pattern:       `\bexecute_concurrent_with_args\s*\(`,
			ObjectType:    "",
			MethodName:    "execute_concurrent_with_args",
			DangerousArgs: []int{1},
			Severity:      rules.Critical,
			Description:   "DataStax cassandra.concurrent.execute_concurrent_with_args(session, statement, parameters) with a tainted CQL statement string enables CQL injection; pass a PreparedStatement or literal CQL with placeholders",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Google BigQuery SQL injection (CWE-89) ---
		// google-cloud-bigquery (Client.query / Client.query_and_wait) plus the
		// pandas_gbq and bigframes ecosystem all submit raw SQL strings to
		// BigQuery. Concatenating untrusted values into the query enables
		// classic SQL injection (BigQuery Standard SQL is a full SQL dialect
		// with DML/DDL). The fix is parameterized queries via QueryJobConfig
		// query_parameters, or @-style named parameters.
		// Refs:
		//   https://cloud.google.com/bigquery/docs/parameterized-queries
		//   https://googleapis.dev/python/bigquery/latest/reference.html
		{
			ID:            "py.bigquery.client.query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `(?:client|bq_client|bigquery_client|bq)\.query\s*\(`,
			ObjectType:    "bigquery.Client",
			MethodName:    "query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "google-cloud-bigquery Client.query() submits raw SQL to BigQuery; tainted concatenated SQL is SQL injection. Use QueryJobConfig with query_parameters and @-named parameters.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.bigquery.client.query_and_wait",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.query_and_wait\s*\(`,
			ObjectType:    "",
			MethodName:    "query_and_wait",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "google-cloud-bigquery >=3.6 Client.query_and_wait() runs raw SQL synchronously; tainted query string is SQL injection. Use QueryJobConfig.query_parameters.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pandas_gbq.read_gbq",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `pandas_gbq\.read_gbq\s*\(`,
			ObjectType:    "pandas_gbq",
			MethodName:    "read_gbq",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "pandas_gbq.read_gbq(query) submits the query string to BigQuery; tainted concatenation is SQL injection. Use configuration={'query':{'queryParameters': ...}} for parameterized queries.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.bigframes.read_gbq_query",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\bread_gbq_query\s*\(`,
			ObjectType:    "",
			MethodName:    "read_gbq_query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "bigframes.pandas.read_gbq_query() runs a raw SQL string against BigQuery; tainted query is SQL injection. Pass parameters via configuration= instead of concatenation.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- LLM agent code-execution sinks (CWE-94 / CWE-89) ---
		// smolagents, AutoGen, and LangChain expose explicit code- and
		// SQL-execution surfaces that take strings and run them. When an
		// LLM-generated string (e.g. tool input forwarded from a chain)
		// reaches one of these, prompt injection becomes arbitrary RCE or
		// SQL injection. Real CVEs: CVE-2023-29374, CVE-2023-39659,
		// CVE-2024-21513, CVE-2024-36480.
		// Note: only sinks with library-unique method names are added here.
		// LangChain APIs that use a bare ".run()" method (PythonREPL.run,
		// ShellTool.run, BashProcess.run, SQLDatabase.run) collide with
		// py.subprocess.call's broad MethodName and are mis-classified as
		// OS-command execution by that earlier sink — the same convention
		// the Neo4j section above documents for session.run / tx.run.
		{
			ID:            "py.smolagents.evaluate_python_code",
			Category:      taint.SnkEval,
			Language:      rules.LangPython,
			Pattern:       `\bevaluate_python_code\s*\(`,
			ObjectType:    "",
			MethodName:    "evaluate_python_code",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "smolagents.local_python_executor.evaluate_python_code() walks a Python AST and executes it; passing an LLM-supplied or otherwise tainted code string yields arbitrary code execution. Restrict authorized_imports and never forward untrusted code unchanged.",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.autogen.execute_code_blocks",
			Category:      taint.SnkEval,
			Language:      rules.LangPython,
			Pattern:       `\.execute_code_blocks\s*\(`,
			ObjectType:    "",
			MethodName:    "execute_code_blocks",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "AutoGen CodeExecutor.execute_code_blocks() runs LLM-generated CodeBlock objects via a local shell, IPython kernel, or Docker container; tainted code blocks are arbitrary code execution. Sandbox via DockerCommandLineCodeExecutor and validate code blocks before execution.",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.langchain.sql_database.run_no_throw",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `\.run_no_throw\s*\(`,
			ObjectType:    "",
			MethodName:    "run_no_throw",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "langchain_community.utilities.SQLDatabase.run_no_throw() executes raw SQL through SQLAlchemy and silently returns the error string on failure (no exception); tainted, LLM-generated, or concatenated queries are SQL injection (CWE-89). Use parameterized queries via sqlalchemy.text() with bound parameters; never pass an LLM-derived string straight through.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- pandas I/O + Keras model loading: untrusted-input sinks ---
		// pandas.read_pickle / read_html / read_xml / read_sql* and
		// keras.models.load_model all take a user-facing first argument
		// (path / URL / raw bytes / SQL string). When that argument is
		// tainted it becomes RCE (pickle / Lambda-layer deserialization),
		// SSRF (read_html / read_xml fetch arbitrary URLs server-side), or
		// SQL injection (read_sql / read_sql_query run a raw query). The
		// read_sql / read_sql_query entries here are the *sink* role —
		// python_sources.go already registers their return value as a
		// second-order DB source.
		{
			ID:            "py.pandas.read_pickle",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `pd\.read_pickle\s*\(|pandas\.read_pickle\s*\(`,
			ObjectType:    "",
			MethodName:    "read_pickle",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "pandas.read_pickle() unpickles a file, URL, or buffer; a tainted path/URL/bytes object enables arbitrary code execution. pandas' own docs warn against loading pickles from untrusted sources — use a safe interchange format (Parquet, Feather, CSV) or restrict inputs to a trusted allowlist.",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.keras.load_model",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `\.load_model\s*\(`,
			ObjectType:    "",
			MethodName:    "load_model",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "keras.models.load_model() / tf.keras.models.load_model() / keras.saving.load_model() loads a saved model; a .h5/SavedModel/.keras archive containing a Lambda layer (and known safe_mode bypasses) executes arbitrary Python on load — CVE-2024-3660 (CVSS 9.8). Also matches mlflow.<flavor>.load_model() / mlflow.pyfunc.load_model(), which deserialize pickled model artifacts — CVE-2024-37052 through CVE-2024-37060. Load models only from trusted sources; for Keras keep safe_mode=True and prefer the native .keras format.",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.pandas.read_html",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `pd\.read_html\s*\(|pandas\.read_html\s*\(`,
			ObjectType:    "",
			MethodName:    "read_html",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "pandas.read_html() accepts a URL as its first argument and fetches it server-side to parse <table> elements; a tainted URL is server-side request forgery (and a tainted local path is arbitrary file disclosure). Validate/allowlist the source, or fetch via a hardened HTTP client and pass the response text.",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "py.pandas.read_xml",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `pd\.read_xml\s*\(|pandas\.read_xml\s*\(`,
			ObjectType:    "",
			MethodName:    "read_xml",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "pandas.read_xml() accepts a URL as its first argument and fetches it server-side; a tainted URL is server-side request forgery, and with parser='lxml' a tainted document can also trigger XXE. Allowlist the source and use parser='etree' for untrusted XML.",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "py.pandas.read_sql.sink",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `pd\.read_sql\s*\(|pandas\.read_sql\s*\(`,
			ObjectType:    "",
			MethodName:    "read_sql",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "pandas.read_sql() runs its first argument as a raw SQL query (or interpolates it as a table name) against the connection; a tainted query/table string is SQL injection. Use parameterized queries via params= with a DBAPI/SQLAlchemy connection, or sqlalchemy.text() with bound parameters — never f-string user input into the query.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pandas.read_sql_query.sink",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangPython,
			Pattern:       `pd\.read_sql_query\s*\(|pandas\.read_sql_query\s*\(`,
			ObjectType:    "",
			MethodName:    "read_sql_query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "pandas.read_sql_query() executes its first argument as a raw SQL query against the connection; a tainted or f-string-built query is SQL injection. Pass parameters via params= (or use sqlalchemy.text() with bound parameters) instead of concatenating user input into the query string.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// =================================================================
		// Mined from public MIT-licensed security-model data.
		// Final batch: sinks for deserialization,
		// crypto, command-exec, template, file-write across Python ecosystem.
		// =================================================================

		{
			ID:            "py.dill.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `dill\.load\s*\(`,
			ObjectType:    "dill",
			MethodName:    "load",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "dill.load() — pickle-compatible deserialization with code-loading hooks",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.dill.loads",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `dill\.loads\s*\(`,
			ObjectType:    "dill",
			MethodName:    "loads",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "dill.loads() — pickle-compatible bytes deserialization (RCE)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.joblib.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `joblib\.load\s*\(`,
			ObjectType:    "joblib",
			MethodName:    "load",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "joblib.load() — uses pickle under the hood; tainted path/stream is RCE",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.jsonpickle.decode",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `jsonpickle\.decode\s*\(`,
			ObjectType:    "jsonpickle",
			MethodName:    "decode",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "jsonpickle.decode() — reconstructs arbitrary Python objects from JSON (CVE-2020-22083)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.numpy.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `numpy\.load\s*\(`,
			ObjectType:    "numpy",
			MethodName:    "load",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "numpy.load() with allow_pickle=True (default in older NumPy) deserializes pickled arrays — RCE",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.marshal.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `marshal\.load\s*\(`,
			ObjectType:    "marshal",
			MethodName:    "load",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "marshal.load() — internal-format deserialization, can deserialize code objects (RCE)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.marshal.loads",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `marshal\.loads\s*\(`,
			ObjectType:    "marshal",
			MethodName:    "loads",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "marshal.loads() — internal-format deserialization, can deserialize code objects (RCE)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.simplejson.loads",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `simplejson\.loads\s*\(`,
			ObjectType:    "simplejson",
			MethodName:    "loads",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "simplejson.loads() — DoS via deeply nested objects when used on untrusted input without a limit",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.simplejson.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `simplejson\.load\s*\(`,
			ObjectType:    "simplejson",
			MethodName:    "load",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "simplejson.load() — DoS via deeply nested objects on untrusted input",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.toml.loads",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `toml\.loads\s*\(`,
			ObjectType:    "toml",
			MethodName:    "loads",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "toml.loads() — TOML parser; DoS via crafted nested structures on untrusted input",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.toml.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `toml\.load\s*\(`,
			ObjectType:    "toml",
			MethodName:    "load",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "toml.load() — TOML parser; DoS on untrusted input",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.torch.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `torch\.load\s*\(`,
			ObjectType:    "torch",
			MethodName:    "load",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "torch.load() — pickle-based PyTorch checkpoint loader; tainted path is RCE (use weights_only=True or safetensors)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.torch.jit.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `torch\.jit\.load\s*\(`,
			ObjectType:    "torch",
			MethodName:    "jit.load",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "torch.jit.load() — loads a TorchScript module from a tainted file (RCE)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.torch.package_importer",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `torch\.package\.PackageImporter\s*\(`,
			ObjectType:    "torch",
			MethodName:    "package.PackageImporter",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "torch.package.PackageImporter() — loads a Python package from a tainted zip (RCE)",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.ujson.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `ujson\.load\s*\(`,
			ObjectType:    "ujson",
			MethodName:    "load",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "ujson.load() — DoS via deeply nested JSON; treat tainted inputs with size/depth limits",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.shelve.open",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `shelve\.open\s*\(`,
			ObjectType:    "shelve",
			MethodName:    "open",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "shelve.open() — pickle-backed key-value store; a tainted path lets attackers control the unpickled values",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.idna.decode",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangPython,
			Pattern:       `idna\.decode\s*\(`,
			ObjectType:    "idna",
			MethodName:    "decode",
			DangerousArgs: []int{0},
			Severity:      rules.Low,
			Description:   "idna.decode() — IDN punycode decoder; CVE-2024-3651 DoS on crafted input",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "py.rsa.encrypt",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `rsa\.encrypt\s*\(`,
			ObjectType:    "rsa",
			MethodName:    "encrypt",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "rsa.encrypt() — PKCS#1 v1.5 padding (no OAEP); chosen-ciphertext attacks (Bleichenbacher)",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "py.rsa.decrypt",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `rsa\.decrypt\s*\(`,
			ObjectType:    "rsa",
			MethodName:    "decrypt",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "rsa.decrypt() — PKCS#1 v1.5 padding (no OAEP); chosen-ciphertext attacks",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "py.rsa.sign",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `rsa\.sign\s*\(`,
			ObjectType:    "rsa",
			MethodName:    "sign",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "rsa.sign() — PKCS#1 v1.5 signature; signs message digests directly with no salting",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "py.rsa.verify",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `rsa\.verify\s*\(`,
			ObjectType:    "rsa",
			MethodName:    "verify",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "rsa.verify() — PKCS#1 v1.5 signature check; matches weak rsa.sign()",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "py.rsa.compute_hash",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `rsa\.compute_hash\s*\(`,
			ObjectType:    "rsa",
			MethodName:    "compute_hash",
			DangerousArgs: []int{0},
			Severity:      rules.Low,
			Description:   "rsa.compute_hash() — direct hash computation, not for password storage",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "py.rsa.sign_hash",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `rsa\.sign_hash\s*\(`,
			ObjectType:    "rsa",
			MethodName:    "sign_hash",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "rsa.sign_hash() — PKCS#1 v1.5 raw-hash signing",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "py.hmac.digest",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `hmac\.digest\s*\(`,
			ObjectType:    "hmac",
			MethodName:    "digest",
			DangerousArgs: []int{1},
			Severity:      rules.Medium,
			Description:   "hmac.digest() — used for password hashing exposes the secret to timing attacks; use hmac.compare_digest()",
			CWEID:         "CWE-916",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "py.cryptography.hash",
			Category:      taint.SnkCrypto,
			Language:      rules.LangPython,
			Pattern:       `hashes\.Hash\s*\(`,
			ObjectType:    "cryptography",
			MethodName:    "hashes.Hash",
			DangerousArgs: []int{0},
			Severity:      rules.Low,
			Description:   "cryptography.hazmat.primitives.hashes.Hash() — pluggable hash factory; ensure the algorithm chosen is not MD5/SHA1 for security uses",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "py.paramiko.proxycommand",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `paramiko\.ProxyCommand\s*\(`,
			ObjectType:    "paramiko",
			MethodName:    "ProxyCommand",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "paramiko.ProxyCommand() — runs a shell command for SSH proxying; tainted command is OS-command injection",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.pexpect.popen_spawn",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `pexpect\.popen_spawn\.PopenSpawn\s*\(|popen_spawn\.PopenSpawn\s*\(`,
			ObjectType:    "pexpect",
			MethodName:    "popen_spawn.PopenSpawn",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "pexpect.popen_spawn.PopenSpawn() — spawns a subprocess with the given command line (RCE if tainted)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.asyncio.subprocess_exec",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `asyncio\.create_subprocess_exec\s*\(|asyncio\.subprocess\.create_subprocess_exec\s*\(`,
			ObjectType:    "asyncio",
			MethodName:    "create_subprocess_exec",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "asyncio.create_subprocess_exec() — async subprocess; tainted argv is OS command injection",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.asyncio.subprocess_shell",
			Category:      taint.SnkCommand,
			Language:      rules.LangPython,
			Pattern:       `asyncio\.create_subprocess_shell\s*\(|asyncio\.subprocess\.create_subprocess_shell\s*\(`,
			ObjectType:    "asyncio",
			MethodName:    "create_subprocess_shell",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "asyncio.create_subprocess_shell() — runs a tainted string through /bin/sh; RCE",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.chevron.render",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `chevron\.render\s*\(`,
			ObjectType:    "chevron",
			MethodName:    "render",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "chevron.render() — Mustache renderer; a tainted template enables SSTI",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.trender.trender",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `\bTRender\s*\(`,
			ObjectType:    "trender",
			MethodName:    "TRender",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "trender.TRender() — template renderer; tainted template enables SSTI",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "py.io.fileio",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `io\.FileIO\s*\(`,
			ObjectType:    "io",
			MethodName:    "FileIO",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "io.FileIO() — opens a raw file at a path; tainted path is path traversal",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.io.open_code",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `io\.open_code\s*\(`,
			ObjectType:    "io",
			MethodName:    "open_code",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "io.open_code() — open a file for use as Python code; tainted path is path traversal",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.tempfile.mkstemp",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `tempfile\.mkstemp\s*\(`,
			ObjectType:    "tempfile",
			MethodName:    "mkstemp",
			DangerousArgs: []int{0, 1, 2},
			Severity:      rules.Medium,
			Description:   "tempfile.mkstemp() — tainted dir/prefix/suffix lets the attacker control where the temp file lands",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.tempfile.mkdtemp",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `tempfile\.mkdtemp\s*\(`,
			ObjectType:    "tempfile",
			MethodName:    "mkdtemp",
			DangerousArgs: []int{0, 1, 2},
			Severity:      rules.Medium,
			Description:   "tempfile.mkdtemp() — tainted dir/prefix/suffix lets the attacker control where the temp dir lands",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.tempfile.named_temporary_file",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `tempfile\.NamedTemporaryFile\s*\(`,
			ObjectType:    "tempfile",
			MethodName:    "NamedTemporaryFile",
			DangerousArgs: []int{0, 1, 2},
			Severity:      rules.Medium,
			Description:   "tempfile.NamedTemporaryFile() — tainted dir/prefix/suffix controls path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.tempfile.temporary_file",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `tempfile\.TemporaryFile\s*\(`,
			ObjectType:    "tempfile",
			MethodName:    "TemporaryFile",
			DangerousArgs: []int{0, 1, 2},
			Severity:      rules.Medium,
			Description:   "tempfile.TemporaryFile() — tainted dir/prefix/suffix controls path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.tempfile.spooled_temporary_file",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `tempfile\.SpooledTemporaryFile\s*\(`,
			ObjectType:    "tempfile",
			MethodName:    "SpooledTemporaryFile",
			DangerousArgs: []int{0, 1, 2},
			Severity:      rules.Medium,
			Description:   "tempfile.SpooledTemporaryFile() — tainted dir/prefix/suffix controls path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "py.tempfile.temporary_directory",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `tempfile\.TemporaryDirectory\s*\(`,
			ObjectType:    "tempfile",
			MethodName:    "TemporaryDirectory",
			DangerousArgs: []int{0, 1, 2},
			Severity:      rules.Medium,
			Description:   "tempfile.TemporaryDirectory() — tainted dir/prefix/suffix controls path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- CherryPy framework sinks ---
		// CherryPy redirects are performed by raising HTTPRedirect with a
		// target URL: `raise cherrypy.HTTPRedirect(url)`. A tainted URL is an
		// open redirect (CWE-601). The bare `py.redirect` sink keys on the
		// method name "redirect" and would not match "HTTPRedirect", so this
		// CherryPy idiom is genuinely uncovered. Pattern is anchored to the
		// HTTPRedirect constructor (qualified `cherrypy.HTTPRedirect(` or bare
		// from `from cherrypy import HTTPRedirect`).
		{
			ID:            "py.cherrypy.httpredirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangPython,
			Pattern:       `(?:cherrypy\.)?HTTPRedirect\s*\(`,
			ObjectType:    "cherrypy",
			MethodName:    "HTTPRedirect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "CherryPy raise cherrypy.HTTPRedirect(url) with potentially tainted URL (open redirect)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		// CherryPy static file serving: cherrypy.lib.static.serve_file(path)
		// reads and streams a file from a caller-supplied path. A tainted path
		// yields arbitrary file read / path traversal (CWE-22). Distinct from
		// Flask's send_file (py.flask.send_file). Anchored to the serve_file
		// call; ObjectType scopes it to the cherrypy.lib.static module.
		{
			ID:            "py.cherrypy.serve_file",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `serve_file\s*\(`,
			ObjectType:    "cherrypy.lib.static",
			MethodName:    "serve_file",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "CherryPy serve_file() with potentially tainted path (arbitrary file read / path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// =====================================================================
		// ECL2 coverage-breadth cleanup wave — Python sinks
		// Each entry closes a detection category Batou's Python catalog
		// did not yet have a sink for. Every sink is ObjectType/Module-anchored
		// (never a bare empty ObjectType on an ambiguous bare name) and pairs
		// with a sanitizer (added in python_sanitizers.go) so safe usage stays
		// clean. CWEs verified absent or only adjacently covered before adding.
		// =====================================================================

		// --- runpy dynamic code execution (CWE-94) ---
		// runpy.run_path(path) / runpy.run_module(mod_name) locate and EXECUTE a
		// Python file or importable module in a fresh namespace. A tainted path
		// or module name is arbitrary-code-execution (the located code runs at
		// import time). Distinct from importlib.import_module (py.importlib.*),
		// which binds a module object; run_path executes a filesystem path that
		// need not even be importable. Module+RequireModule scopes to runpy.
		{
			ID:            "py.runpy.run",
			Category:      taint.SnkEval,
			Language:      rules.LangPython,
			Pattern:       `runpy\.run_path\s*\(|runpy\.run_module\s*\(`,
			ObjectType:    "runpy",
			MethodName:    "runpy.run_path/run_module",
			Module:        "runpy",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "runpy.run_path()/run_module() executes a Python file or module from a potentially tainted path/name (arbitrary code execution)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- code / codeop interactive interpreter eval (CWE-94) ---
		// code.InteractiveInterpreter().runsource(src) and code.interact() feed
		// a source string to the same compile+exec machinery as eval/exec.
		// codeop.compile_command(src) compiles a single interactive statement.
		// All three execute/compile a caller-supplied program string — RCE when
		// tainted. Anchored to the code/codeop modules. py.compile (stdlib
		// compile()) covers the builtin; this covers the interactive-console API
		// Semgrep flags separately (python.lang.security.audit.exec-detected
		// family / code.interact).
		{
			ID:            "py.code.interact",
			Category:      taint.SnkEval,
			Language:      rules.LangPython,
			Pattern:       `code\.interact\s*\(|\.runsource\s*\(|\.runcode\s*\(|codeop\.compile_command\s*\(`,
			ObjectType:    "code.InteractiveInterpreter",
			MethodName:    "code.interact/runsource/runcode/codeop.compile_command",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Interactive interpreter eval (code.interact/InteractiveInterpreter.runsource/runcode/codeop.compile_command) with a potentially tainted source string (arbitrary code execution)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- string.Template.substitute format-string injection (CWE-1336/CWE-94) ---
		// string.Template(user_controlled_template).substitute(mapping) and
		// str.format_map(mapping) interpolate using a caller-controlled FORMAT
		// STRING. When the template/format string itself is tainted, an attacker
		// supplies `${...}` / `{0.__class__...}` / `{config[SECRET]}` access
		// paths that reach object internals and app config — server-side
		// template / format-string injection and secret disclosure. This is the
		// dangerous direction (tainted *template*), distinct from a safe template
		// with tainted *values*. The tainted payload is the TEMPLATE: for the
		// .substitute/.safe_substitute/.format_map methods that is the RECEIVER
		// (PayloadReceiver, below); for the string.Template(...) constructor it is
		// arg 0 (py.string.template.ctor, further below). Splitting them keeps the
		// receiver-payload methods from false-firing on a tainted MAPPING argument
		// under a constant template, while the constructor still fires on a tainted
		// template argument.
		{
			ID:              "py.string.template.substitute",
			Category:        taint.SnkTemplate,
			Language:        rules.LangPython,
			Pattern:         `\.substitute\s*\(|\.safe_substitute\s*\(|\.format_map\s*\(`,
			ObjectType:      "string.Template",
			MethodName:      "substitute/safe_substitute/format_map",
			PayloadPosition: taint.PayloadReceiver,
			Severity:        rules.High,
			Description:     "str.format_map()/string.Template(...).substitute()/.safe_substitute() called on a potentially tainted TEMPLATE (the receiver) — format-string injection exposing object internals and app config (CWE-1336). The mapping argument holds substituted values and is not the trigger.",
			CWEID:           "CWE-1336",
			OWASPCategory:   "A03:2021-Injection",
		},
		// string.Template(TEMPLATE) constructor: here the tainted payload is the
		// TEMPLATE STRING passed as arg 0 (a different payload position from the
		// .substitute/.format_map methods above, whose template is the receiver).
		// Default PayloadPosition (arg-fire) — byte-identical to the historical
		// `string.Template(` alternative of the combined sink, so the canonical
		// `string.Template(request.args['t']).substitute(x)` flow still fires on
		// the tainted constructor argument.
		{
			ID:            "py.string.template.ctor",
			Category:      taint.SnkTemplate,
			Language:      rules.LangPython,
			Pattern:       `string\.Template\s*\(`,
			ObjectType:    "string.Template",
			MethodName:    "string.Template",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "string.Template(...) constructed from a potentially tainted template/format string — format-string injection exposing object internals and app config (CWE-1336)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- boto3 S3 download_file path traversal (CWE-22) ---
		// client.download_file(Bucket, Key, Filename) and
		// download_fileobj(...) WRITE the object to a local path. A tainted
		// Filename (3rd positional / Filename kwarg) is arbitrary-file-write /
		// path traversal — `../../etc/...` escapes the intended directory.
		// Receiver-typed to boto3.S3.Client (already a source ObjectType in this
		// catalog). DangerousArg 2 = the local Filename, NOT the remote Key.
		{
			ID:            "py.boto3.s3.download_file",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangPython,
			Pattern:       `\.download_file\s*\(|\.download_fileobj\s*\(`,
			ObjectType:    "boto3.S3.Client",
			MethodName:    "download_file/download_fileobj",
			DangerousArgs: []int{2},
			Severity:      rules.High,
			Description:   "boto3 S3 download_file()/download_fileobj() with a potentially tainted local Filename (path traversal / arbitrary file write outside the target directory)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- setattr() mass assignment / arbitrary attribute write (CWE-915) ---
		// setattr(obj, name, value) where `name` is attacker-controlled lets a
		// request body overwrite arbitrary object/model attributes (privilege
		// fields, ORM internals, __class__). This is the Python expression of
		// mass assignment (Semgrep python.lang.security.audit ... and the
		// django/flask mass-assignment family). The DANGEROUS argument is the
		// attribute NAME (arg 1), not the value — a tainted name picks which
		// field gets written. ObjectType "@global" marks a builtin (consistent
		// with other builtins in this catalog) so the receiver heuristic does
		// not require a typed receiver.
		{
			ID:            "py.setattr.massassign",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangPython,
			Pattern:       `(?:^|[^A-Za-z0-9_.])setattr\s*\(`,
			ObjectType:    "@global",
			MethodName:    "setattr",
			DangerousArgs: []int{1},
			// PayloadArgOnly: fire strictly on the tainted NAME (arg 1), never on a
			// tainted receiver. setattr() is a global builtin (no receiver of its
			// own), so this is inert today — but it makes the name-arg-only contract
			// declarative and consistent with the Ruby reflective sinks
			// (instance_variable_set/define_method) that share this exact shape.
			PayloadPosition: taint.PayloadArgOnly,
			// RejectConstrainedName: suppress the BOUNDED-name framework idioms that
			// would otherwise false-fire — setattr(self, field.name, v) (model-
			// metadata write), setattr(self, request.method.lower(), v), a literal
			// name, or a literal dispatch-table key. A genuinely tainted name
			// (setattr(obj, request.args['k'], v)) still fires (CWE-915).
			RejectConstrainedName: true,
			Severity:              rules.High,
			Description:           "setattr() with a potentially tainted attribute name — mass assignment: a request value selects which object/model attribute is overwritten (privilege fields, ORM internals)",
			CWEID:                 "CWE-915",
			OWASPCategory:         "A08:2021-Software and Data Integrity Failures",
		},

		// --- getattr() unsafe reflection / arbitrary attribute read-or-call (CWE-470) ---
		// getattr(obj, name[, default]) with an attacker-controlled NAME lets a
		// request value select which attribute is read — and, when the looked-up
		// attribute is then invoked (getattr(obj, request.args['x'])()), which
		// method is called. This is the Python expression of unsafe reflection
		// (Semgrep's `dangerous-getattr`): a real coverage gap Batou had no sink
		// for. The DANGEROUS argument is the attribute NAME (arg 1), not the object
		// or the default. ObjectType "@global" marks the bare builtin (no
		// receiver), matching the setattr entry above.
		//
		// RejectConstrainedName is what makes adding getattr safe: it suppresses
		// the two pervasive SAFE framework idioms that previously NO-GO'd this sink
		// — Flask/Django HTTP-verb dispatch getattr(self, request.method.lower())
		// and model-metadata iteration getattr(obj, field.name) — plus a string-
		// literal name and a literal dispatch-table key. An OPEN tainted name
		// (getattr(obj, request.args['x'])) is not constrained and still fires.
		{
			ID:                    "py.getattr.reflection",
			Category:              taint.SnkEval,
			Language:              rules.LangPython,
			Pattern:               `(?:^|[^A-Za-z0-9_.])getattr\s*\(`,
			ObjectType:            "@global",
			MethodName:            "getattr",
			DangerousArgs:         []int{1},
			PayloadPosition:       taint.PayloadArgOnly,
			RejectConstrainedName: true,
			Severity:              rules.High,
			Description:           "getattr() with a potentially tainted attribute name — unsafe reflection: a request value selects which attribute is read or (when the result is invoked) which method is called. A string-literal name, an HTTP-verb dispatch (request.method), or model-metadata iteration (field.name) does not fire.",
			CWEID:                 "CWE-470",
			OWASPCategory:         "A03:2021-Injection",
		},

		// --- werkzeug.utils.redirect open redirect (CWE-601) ---
		// werkzeug.utils.redirect(location) (Flask's redirect() is re-exported
		// from here) builds a 302 to a caller-supplied location. A tainted
		// location is an open redirect. The existing py.redirect anchors on a
		// bare `redirect(` shape; this entry adds the explicit
		// werkzeug.utils.redirect qualified form so the SSRF/redirect sanitizers
		// (url_has_allowed_host_and_scheme) gate it. ObjectType scopes it.
		{
			ID:            "py.werkzeug.redirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangPython,
			Pattern:       `werkzeug\.utils\.redirect\s*\(|utils\.redirect\s*\(`,
			ObjectType:    "werkzeug.utils",
			MethodName:    "werkzeug.utils.redirect",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "werkzeug.utils.redirect() with a potentially tainted location (open redirect)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- aiohttp web.HTTPFound open redirect (CWE-601) ---
		// aiohttp raises web.HTTPFound(location) (and HTTPMovedPermanently /
		// HTTPSeeOther / HTTPTemporaryRedirect) to issue a redirect. The
		// existing HTTPFound entry is Pyramid-typed; aiohttp's web.HTTPFound is
		// a separate class. Anchor to the aiohttp.web module so safe redirects
		// to validated locations (url_has_allowed_host_and_scheme) stay clean.
		{
			ID:            "py.aiohttp.httpfound",
			Category:      taint.SnkRedirect,
			Language:      rules.LangPython,
			Pattern:       `web\.HTTPFound\s*\(|web\.HTTPMovedPermanently\s*\(|web\.HTTPSeeOther\s*\(|web\.HTTPTemporaryRedirect\s*\(`,
			ObjectType:    "aiohttp.web",
			MethodName:    "web.HTTPFound/HTTPMovedPermanently/HTTPSeeOther/HTTPTemporaryRedirect",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "aiohttp web.HTTPFound/HTTPSeeOther/HTTPMovedPermanently redirect with a potentially tainted location (open redirect)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- bottle.redirect open redirect (CWE-601) ---
		// bottle.redirect(url) issues an HTTP redirect to a caller-supplied URL.
		// Module+RequireModule scopes to bottle so a local helper named
		// `redirect` does not light up.
		{
			ID:            "py.bottle.redirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangPython,
			Pattern:       `bottle\.redirect\s*\(`,
			ObjectType:    "bottle",
			MethodName:    "bottle.redirect",
			Module:        "bottle",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "bottle.redirect() with a potentially tainted URL (open redirect)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- httpx/requests proxies SSRF via tainted proxy URL (CWE-918) ---
		// Building an httpx.Client(proxies=...) / requests with a tainted proxy
		// URL routes all outbound traffic through an attacker-chosen host —
		// SSRF/exfiltration. Distinct from the existing httpx.get(url) SSRF
		// sinks (which flag the *request* URL); here the danger is the proxy.
		// Anchored to httpx.Client/requests proxies kwarg shape.
		{
			ID:            "py.httpx.client.proxy",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangPython,
			Pattern:       `httpx\.(?:Client|AsyncClient)\s*\([^)]*\bprox(?:y|ies)\s*=|requests\.\w+\s*\([^)]*\bproxies\s*=`,
			ObjectType:    "httpx",
			MethodName:    "Client/AsyncClient",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "httpx.Client(proxy=)/requests(proxies=) with a potentially tainted proxy URL — outbound traffic routed through an attacker-chosen host (SSRF/exfiltration)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- sqlite3 module-level connect() path (CWE-22) ---
		// sqlite3.connect(database) opens (creating if absent) a DB file at the
		// given path. A tainted path is arbitrary file create/open outside the
		// intended location. The existing aiosqlite entry covers the async lib;
		// stdlib sqlite3.connect is separate. ":memory:" / constant paths stay
		// clean (no taint reaches arg 0). Module-scoped to sqlite3.
		{
			ID:            "py.sqlite3.connect.path",
			Category:      taint.SnkFileRead,
			Language:      rules.LangPython,
			Pattern:       `sqlite3\.connect\s*\(`,
			ObjectType:    "sqlite3",
			MethodName:    "sqlite3.connect",
			Module:        "sqlite3",
			RequireModule: true,
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "sqlite3.connect() with a potentially tainted database path (arbitrary file create/open / path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
	}
}
