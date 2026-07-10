package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (rubyCatalog) Sinks() []taint.SinkDef {
	return []taint.SinkDef{
		// SQL injection
		{ID: "ruby.activerecord.execute", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.execute\s*\(`, ObjectType: "ActiveRecord", MethodName: "execute", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL execution via ActiveRecord", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.activerecord.exec_query", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.exec_query\s*\(`, ObjectType: "", MethodName: "exec_query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL exec_query via ActiveRecord", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.activerecord.connection.execute", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `ActiveRecord::Base\.connection\.execute\s*\(`, ObjectType: "connection", MethodName: "execute", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Direct SQL execution via ActiveRecord connection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		// AR .where()/.order() raw-string-argument SQLi. ObjectType is "" (wildcard
		// on the model-class receiver — `User.where(...)`, `Post.order(...)` — which
		// is never literally named "ActiveRecord"), but the Pattern is the precise
		// discriminator and is ENFORCED by tsflow's weakSinkPatternOK: it has no
		// `.*`/`.+` (which weakSinkPatternOK would skip) so the string-literal +
		// `#{` interpolation (or string-concat) shape must be present in the call
		// text before a weak match fires. The Pattern is delimiter-aware — it
		// matches a double-quoted OR a single-quoted Ruby string and scans only up
		// to the OTHER quote so the common `where("id = '#{x}'")` shape (a SQL
		// single-quoted literal inside a Ruby double-quoted string) is caught while
		// a fully-static `where("name = 'bob'")` is not. This keeps the safe
		// parameterized form (`.where("x = ?", v)`), the named-bind form
		// (`.where("x = :n", n: v)`), the hash form (`.where(name: v)`), and the
		// pure-literal form (`.where("active = true")`) from matching, while the
		// interpolation/concat form does. Mirrors the sibling
		// select/having/joins/group/from entries which already carry ObjectType ""
		// (those rely on `.*` arg-taint; these are stricter). `.where.not` and
		// `.reorder` are folded in as raw-SQL-accepting variants.
		// MethodName "where/not" registers BOTH `where` (the dominant
		// `User.where("...#{x}...")` form) and `not` (the chained
		// `User.where.not("...#{x}...")` negation form, whose call-node method name
		// is `not`). The enforced Pattern requires the full `.where`/`.where.not`
		// interpolation shape, so registering `not` cannot collide with an
		// unrelated `.not(...)` call.
		{ID: "ruby.activerecord.where.interpolation", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.where(?:\.not)?\s*\(\s*(?:"[^"]*(?:#\{|"\s*\+|\+\s*")|'[^']*(?:#\{|'\s*\+|\+\s*'))`, ObjectType: "", MethodName: "where/not", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via string interpolation/concatenation in ActiveRecord .where()/.where.not()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.activerecord.order.interpolation", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.(?:order|reorder)\s*\(\s*(?:"[^"]*(?:#\{|"\s*\+|\+\s*")|'[^']*(?:#\{|'\s*\+|\+\s*'))`, ObjectType: "", MethodName: "order/reorder", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL injection via string interpolation/concatenation in ActiveRecord .order()/.reorder()", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// PG gem SQL sinks (raw PostgreSQL driver — bypasses ActiveRecord parameterization)
		{ID: "ruby.pg.exec_params", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.exec_params\s*\(`, ObjectType: "PG::Connection", MethodName: "exec_params", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "PG::Connection#exec_params — first arg is SQL; interpolating user input into the SQL string bypasses parameter binding", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.pg.async_exec", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.async_exec\s*\(`, ObjectType: "PG::Connection", MethodName: "async_exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "PG::Connection#async_exec — raw SQL execution (asynchronous), no parameter binding", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.pg.sync_exec", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.sync_exec\s*\(`, ObjectType: "PG::Connection", MethodName: "sync_exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "PG::Connection#sync_exec — raw SQL execution (synchronous libpq), no parameter binding", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.pg.send_query", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.send_query\s*\(`, ObjectType: "PG::Connection", MethodName: "send_query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "PG::Connection#send_query — raw SQL dispatched without waiting for result, no parameter binding", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.pg.prepare", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.prepare\s*\(`, ObjectType: "PG::Connection", MethodName: "prepare", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "PG::Connection#prepare — second arg is the SQL statement body; user input interpolated into it bypasses subsequent parameter binding in exec_prepared", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// Mysql2 gem SQL sinks (raw MySQL driver — bypasses ActiveRecord parameterization)
		{ID: "ruby.mysql2.query", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.query\s*\(`, ObjectType: "Mysql2::Client", MethodName: "query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Mysql2::Client#query — raw SQL execution; no server-side parameter binding, interpolation is exploitable", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.mysql2.prepare", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.prepare\s*\(`, ObjectType: "Mysql2::Client", MethodName: "prepare", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Mysql2::Client#prepare — SQL statement body; user input interpolated into it bypasses the subsequent parameter binding on the Mysql2::Statement", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// SQLite3 gem SQL sinks (sqlite3-ruby — the canonical SQLite binding and the
		// raw connection behind the ActiveRecord sqlite3 adapter). The result-row READ
		// methods (get_first_row/get_first_value) are already modeled as SrcDatabase
		// sources; these are the matching execution sinks. `execute` itself is already
		// caught by the broader ruby.sequel.db.execute entry (Sequel::Database matches
		// db/database/sqlite receivers), so only the methods with no existing coverage
		// are added here.
		{ID: "ruby.sqlite3.execute2", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.execute2\s*\(`, ObjectType: "SQLite3::Database", MethodName: "execute2", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQLite3::Database#execute2 — first arg is raw SQL (returns rows prefixed by a header row); interpolating user input is exploitable, only bind parameters are safe", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.sqlite3.execute_batch", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.execute_batch\s*\(`, ObjectType: "SQLite3::Database", MethodName: "execute_batch", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQLite3::Database#execute_batch — first arg is one or more semicolon-separated SQL statements; user input interpolated into it enables stacked-query injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.sqlite3.execute_batch2", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.execute_batch2\s*\(`, ObjectType: "SQLite3::Database", MethodName: "execute_batch2", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQLite3::Database#execute_batch2 — first arg is a raw SQL batch executed and returned; no bind-parameter support, interpolation is exploitable", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.sqlite3.query", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.query\s*\(`, ObjectType: "SQLite3::Database", MethodName: "query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQLite3::Database#query — first arg is raw SQL (returns a ResultSet); interpolating user input bypasses parameter binding", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.sqlite3.prepare", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.prepare\s*\(`, ObjectType: "SQLite3::Database", MethodName: "prepare", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQLite3::Database#prepare — first arg is the SQL statement body; user input interpolated into it bypasses the subsequent bind on the SQLite3::Statement", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// TinyTds gem SQL sink (FreeTDS / SQL Server). The result of #execute is already
		// modeled as a SrcDatabase source (second-order); this is the matching sink for
		// the SQL string argument. TinyTds has no server-side parameter binding — only
		// TinyTds::Client#escape (modeled as a sanitizer) neutralizes interpolated input.
		{ID: "ruby.tiny_tds.execute", Category: taint.SnkSQLQuery, Language: rules.LangRuby, Pattern: `\.execute\s*\(`, ObjectType: "TinyTds::Client", MethodName: "execute", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "TinyTds::Client#execute — raw SQL execution against SQL Server; no parameter binding, interpolating user input is exploitable", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// Command injection
		{ID: "ruby.system", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `\bsystem\s*\(`, ObjectType: "", MethodName: "system", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via system()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.exec", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `\bexec\s*\(`, ObjectType: "", MethodName: "exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via exec()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.backticks", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: "`.+`", ObjectType: "", MethodName: "backticks", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via backticks", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.percent_x", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `%x\(`, ObjectType: "", MethodName: "%x()", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via %x()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.open3.capture2", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `Open3\.capture2\s*\(`, ObjectType: "Open3", MethodName: "capture2", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command via Open3.capture2", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.open3.capture3", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `Open3\.capture3\s*\(`, ObjectType: "Open3", MethodName: "capture3", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command via Open3.capture3", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.open3.popen3", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `Open3\.popen3\s*\(`, ObjectType: "Open3", MethodName: "popen3", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command via Open3.popen3", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.open3.pipeline", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `Open3\.pipeline\s*\(`, ObjectType: "Open3", MethodName: "pipeline", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command pipeline via Open3.pipeline", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.open3.capture2e", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `Open3\.capture2e\s*\(`, ObjectType: "Open3", MethodName: "capture2e", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command via Open3.capture2e (merged stdout+stderr)", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.open3.popen2", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `Open3\.popen2\s*\(`, ObjectType: "Open3", MethodName: "popen2", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command via Open3.popen2", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.open3.popen2e", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `Open3\.popen2e\s*\(`, ObjectType: "Open3", MethodName: "popen2e", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command via Open3.popen2e (merged stdout+stderr)", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.open3.pipeline_start", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `Open3\.pipeline_start\s*\(`, ObjectType: "Open3", MethodName: "pipeline_start", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command pipeline via Open3.pipeline_start", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.open3.pipeline_r", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `Open3\.pipeline_r\s*\(`, ObjectType: "Open3", MethodName: "pipeline_r", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command pipeline via Open3.pipeline_r", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.open3.pipeline_w", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `Open3\.pipeline_w\s*\(`, ObjectType: "Open3", MethodName: "pipeline_w", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command pipeline via Open3.pipeline_w", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.open3.pipeline_rw", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `Open3\.pipeline_rw\s*\(`, ObjectType: "Open3", MethodName: "pipeline_rw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command pipeline via Open3.pipeline_rw", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.io.popen", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `IO\.popen\s*\(`, ObjectType: "IO", MethodName: "popen", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command via IO.popen", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.process.spawn", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `Process\.spawn\s*\(`, ObjectType: "Process", MethodName: "spawn", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command via Process.spawn", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.pty.spawn", Category: taint.SnkCommand, Language: rules.LangRuby, Pattern: `PTY\.spawn\s*\(`, ObjectType: "PTY", MethodName: "spawn", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command via PTY.spawn (pseudoterminal)", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

		// Code evaluation
		{ID: "ruby.eval", Category: taint.SnkEval, Language: rules.LangRuby, Pattern: `\beval\s*\(`, ObjectType: "", MethodName: "eval", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Dynamic code evaluation via eval()", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
		// send/public_send are DangerousArgs:[0]=method NAME with PayloadArgOnly:
		// the genuine reflective-dispatch RCE is a TAINTED method name
		// (`obj.public_send(params[:m])`). The idiomatic Rails attribute-writer
		// form `record.public_send("#{attr}=", value)` / `record.public_send(:save)`
		// runs on a DB-loaded (internally-tainted) RECEIVER with a literal/whitelisted
		// name — PayloadArgOnly turns off the receiver-taint fallback so that benign
		// shape no longer false-fires CWE-94, while a tainted arg-0 still fires.
		{ID: "ruby.send", Category: taint.SnkEval, Language: rules.LangRuby, Pattern: `\.send\s*\(`, ObjectType: "", MethodName: "send", DangerousArgs: []int{0}, PayloadPosition: taint.PayloadArgOnly, Severity: rules.High, Description: "Dynamic method invocation via send()", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.public_send", Category: taint.SnkEval, Language: rules.LangRuby, Pattern: `\.public_send\s*\(`, ObjectType: "", MethodName: "public_send", DangerousArgs: []int{0}, PayloadPosition: taint.PayloadArgOnly, Severity: rules.High, Description: "Dynamic method invocation via public_send()", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

		// XSS
		// render html:/inline:/file:/text: are Rails ActionController keyword-arg
		// render forms. They were keyed ObjectType:"ActionController" +
		// MethodName:"render html:" etc., but extractMethodNames("render html:")
		// mangles the space+colon to an empty final component, so the sink was
		// registered under NO key in sinksByMethod and was NEVER a candidate for a
		// `render` call (dead). Re-key bare: ObjectType:"" + MethodName:"render"
		// indexes under "render"; the empty-ObjectType wildcard branch then
		// re-validates the call text against the tight Pattern (weakSinkPatternOK),
		// so ONLY literal `render html:/inline:/file:/text:` pass while
		// `render :index` / `render json:` / `render partial:` / `render @user` fail.
		{ID: "ruby.rails.render.html", Category: taint.SnkHTMLOutput, Language: rules.LangRuby, Pattern: `render\s+html\s*:`, ObjectType: "", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.High, Description: "Rails render html (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.rails.render.inline", Category: taint.SnkHTMLOutput, Language: rules.LangRuby, Pattern: `render\s+inline\s*:`, ObjectType: "", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.High, Description: "Rails render inline (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

		// File serving via render
		{ID: "ruby.rails.render.file", Category: taint.SnkFileRead, Language: rules.LangRuby, Pattern: `render\s+file\s*:`, ObjectType: "", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.High, Description: "Rails render file: with tainted path (arbitrary file read, CVE-2019-5418)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// Redirect
		{ID: "ruby.rails.redirect_to", Category: taint.SnkRedirect, Language: rules.LangRuby, Pattern: `redirect_to\s*\(`, ObjectType: "ActionController", MethodName: "redirect_to", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via redirect_to", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},

		// File operations
		{ID: "ruby.file.open", Category: taint.SnkFileWrite, Language: rules.LangRuby, Pattern: `File\.open\s*\(`, ObjectType: "File", MethodName: "open", DangerousArgs: []int{0}, Severity: rules.High, Description: "File open with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "ruby.file.write", Category: taint.SnkFileWrite, Language: rules.LangRuby, Pattern: `File\.write\s*\(`, ObjectType: "File", MethodName: "write", DangerousArgs: []int{0}, Severity: rules.High, Description: "File write with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "ruby.fileutils", Category: taint.SnkFileWrite, Language: rules.LangRuby, Pattern: `FileUtils\.`, ObjectType: "FileUtils", MethodName: "FileUtils", DangerousArgs: []int{-1}, Severity: rules.High, Description: "FileUtils operation with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// CSV / spreadsheet formula injection (CWE-1236) — CSV.generate /
		// CSV.open yield a CSV object whose #add_row (alias for #<<) appends
		// a record; when the record holds user-controlled values, cells
		// beginning with =, +, -, @, tab or CR are interpreted as formulas
		// by Excel / LibreOffice / Google Sheets when the file is opened
		// (DDE / command execution on the viewer's machine). Receiver-bound
		// to a CSV object (`csv`) so unrelated #add_row calls don't match.
		{ID: "ruby.csv.addrow", Category: taint.SnkCSV, Language: rules.LangRuby, Pattern: `\.add_row\s*\(`, ObjectType: "CSV", MethodName: "add_row", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "CSV#add_row with user-controlled record (from CSV.generate/CSV.open) — values beginning with =, +, -, @ become formulas when the CSV is opened in a spreadsheet (CSV/formula injection)", CWEID: "CWE-1236", OWASPCategory: "A03:2021-Injection"},

		// Unrestricted file upload (CWE-434) — a Rails ActionDispatch::Http::
		// UploadedFile (params[:file]) persisted to disk without validating its
		// extension / MIME type / content lets an attacker drop a webshell.
		// CarrierWave: uploader.store!(file) / model.attr.store! — `store!` is a
		// distinctive bang method. Shrine: uploader.upload(io) — receiver-bound
		// to a Shrine uploader. (Plain File.write / FileUtils.cp of an upload
		// are already covered by the CWE-22 path-traversal sinks above.)
		{ID: "ruby.carrierwave.store", Category: taint.SnkUpload, Language: rules.LangRuby, Pattern: `\.store!`, ObjectType: "", MethodName: "store!", DangerousArgs: []int{0}, Severity: rules.High, Description: "CarrierWave uploader.store!() persisting an uploaded file without extension/MIME validation (unrestricted file upload)", CWEID: "CWE-434", OWASPCategory: "A04:2021-Insecure Design"},
		{ID: "ruby.shrine.upload", Category: taint.SnkUpload, Language: rules.LangRuby, Pattern: `\.upload\s*\(`, ObjectType: "Shrine", MethodName: "upload", DangerousArgs: []int{0}, Severity: rules.High, Description: "Shrine uploader.upload(io) persisting an uploaded file without extension/MIME validation (unrestricted file upload)", CWEID: "CWE-434", OWASPCategory: "A04:2021-Insecure Design"},

		// Deserialization
		{ID: "ruby.marshal.load", Category: taint.SnkDeserialize, Language: rules.LangRuby, Pattern: `Marshal\.load\s*\(`, ObjectType: "Marshal", MethodName: "load", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Unsafe deserialization via Marshal.load", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures", Advisory: "CWE-502 / Ruby Marshal docs warning — Marshal.load() on untrusted data instantiates arbitrary objects and is a known RCE gadget vector", AdvisoryID: "CWE-502"},
		{ID: "ruby.marshal.restore", Category: taint.SnkDeserialize, Language: rules.LangRuby, Pattern: `Marshal\.restore\s*\(`, ObjectType: "Marshal", MethodName: "restore", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Unsafe deserialization via Marshal.restore (alias for Marshal.load)", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
		{ID: "ruby.yaml.load", Category: taint.SnkDeserialize, Language: rules.LangRuby, Pattern: `YAML\.load\s*\(`, ObjectType: "YAML", MethodName: "load", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Unsafe YAML deserialization", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures", Advisory: "CVE-2013-0156 (Rails/Psych) — YAML.load() on untrusted input instantiates arbitrary Ruby objects (RCE); use YAML.safe_load()", AdvisoryID: "CVE-2013-0156"},
		{ID: "ruby.yaml.unsafe_load", Category: taint.SnkDeserialize, Language: rules.LangRuby, Pattern: `YAML\.unsafe_load\s*\(`, ObjectType: "YAML", MethodName: "unsafe_load", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Explicit unsafe YAML deserialization (Ruby 3.1+)", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
		{ID: "ruby.psych.unsafe_load", Category: taint.SnkDeserialize, Language: rules.LangRuby, Pattern: `Psych\.unsafe_load\s*\(`, ObjectType: "Psych", MethodName: "unsafe_load", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Unsafe YAML deserialization via Psych backend (Ruby 3.1+)", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
		{ID: "ruby.oj.load", Category: taint.SnkDeserialize, Language: rules.LangRuby, Pattern: `Oj\.load\s*\(`, ObjectType: "Oj", MethodName: "load", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Oj JSON deserialization with potential object mode RCE", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

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
		// ObjectType "" (was "ActionView"): raw() is a bare ActionView helper —
		// the call `raw(x)` carries no `ActionView` receiver, so a receiver-typed
		// ObjectType never matched and the sink was dead. The empty ObjectType
		// routes it through tsflow's weak-sink path, which re-validates the call
		// against the `\braw\s*\(` Pattern (weakSinkPatternOK) while the
		// SnkHTMLOutput sanitizers (h/sanitize/content_tag/escape_html/…) still
		// suppress safe/escaped/constant uses.
		{ID: "ruby.rails.raw", Category: taint.SnkHTMLOutput, Language: rules.LangRuby, Pattern: `\braw\s*\(`, ObjectType: "", MethodName: "raw", DangerousArgs: []int{0}, Severity: rules.High, Description: "Rails raw() bypasses HTML escaping (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		// ObjectType "" (was "String"): the receiver of `x.html_safe` is an
		// arbitrary expression (e.g. `params[:x]`), not literally a `String`-typed
		// receiver, so the type check never matched and the sink was dead. Empty
		// ObjectType + the `\.html_safe` Pattern (weak-sink re-validation) fires on
		// any-receiver `.html_safe`; HTML-output sanitizers keep escaped uses safe.
		{ID: "ruby.rails.html_safe", Category: taint.SnkHTMLOutput, Language: rules.LangRuby, Pattern: `\.html_safe`, ObjectType: "", MethodName: "html_safe", DangerousArgs: []int{0}, Severity: rules.High, Description: "Marking tainted string as html_safe (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.rails.safe_concat", Category: taint.SnkHTMLOutput, Language: rules.LangRuby, Pattern: `safe_concat\s*\(`, ObjectType: "", MethodName: "safe_concat", DangerousArgs: []int{0}, Severity: rules.High, Description: "ActionView safe_concat bypasses HTML auto-escaping (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.rails.render.text", Category: taint.SnkHTMLOutput, Language: rules.LangRuby, Pattern: `render\s+text\s*:`, ObjectType: "", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.High, Description: "Rails render text: sends text/html content-type by default (XSS in Rails 4)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.rails.stream.write", Category: taint.SnkHTMLOutput, Language: rules.LangRuby, Pattern: `response\.stream\.write\s*\(`, ObjectType: "response.stream", MethodName: "stream.write", DangerousArgs: []int{0}, Severity: rules.High, Description: "ActionController::Live stream write bypasses HTML auto-escaping (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

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
		{ID: "ruby.crypto.openssl.ecb_mode", Category: taint.SnkCrypto, Language: rules.LangRuby, Pattern: `OpenSSL::Cipher\.new\s*\(\s*['"][^'"]*ECB`, ObjectType: "OpenSSL::Cipher", MethodName: "Cipher.new(ECB)", DangerousArgs: []int{0}, Severity: rules.High, Description: "ECB mode cipher usage (no diffusion, use CBC/GCM)", CWEID: "CWE-327", OWASPCategory: "A02:2021-Cryptographic Failures"},

		// Insecure random (CWE-338)
		{ID: "ruby.crypto.insecure_rand", Category: taint.SnkCrypto, Language: rules.LangRuby, Pattern: `(?:^|[^.\w])rand\s*\(|(?:^|[^.\w])srand\s*\(`, ObjectType: "Kernel", MethodName: "rand", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Non-cryptographic random for security (use SecureRandom instead)", CWEID: "CWE-338", OWASPCategory: "A02:2021-Cryptographic Failures"},

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
		{ID: "ruby.net_ldap.add", Category: taint.SnkLDAP, Language: rules.LangRuby, Pattern: `(?:ldap|LDAP)\.add\s*\([^)]*\bdn\s*[:=]`, ObjectType: "Net::LDAP", MethodName: "add", DangerousArgs: []int{0}, Severity: rules.High, Description: "Net::LDAP#add with tainted DN — attacker can inject entries under arbitrary DNs (CWE-90)", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.net_ldap.modify", Category: taint.SnkLDAP, Language: rules.LangRuby, Pattern: `(?:ldap|LDAP)\.modify\s*\([^)]*\bdn\s*[:=]`, ObjectType: "Net::LDAP", MethodName: "modify", DangerousArgs: []int{0}, Severity: rules.High, Description: "Net::LDAP#modify with tainted DN — attacker can modify attributes on arbitrary entries (CWE-90)", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.net_ldap.delete", Category: taint.SnkLDAP, Language: rules.LangRuby, Pattern: `(?:ldap|LDAP)\.delete\s*\([^)]*\bdn\s*[:=]`, ObjectType: "Net::LDAP", MethodName: "delete", DangerousArgs: []int{0}, Severity: rules.High, Description: "Net::LDAP#delete with tainted DN — attacker can delete arbitrary directory entries (CWE-90)", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.net_ldap.bind_as", Category: taint.SnkLDAP, Language: rules.LangRuby, Pattern: `(?:ldap|LDAP)\.bind_as\s*\(`, ObjectType: "Net::LDAP", MethodName: "bind_as", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Net::LDAP#bind_as with tainted filter/base — LDAP authentication bypass via filter injection (CWE-90)", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.net_ldap.modify_rdn", Category: taint.SnkLDAP, Language: rules.LangRuby, Pattern: `(?:ldap|LDAP)\.(?:modify_rdn|rename)\s*\(`, ObjectType: "Net::LDAP", MethodName: "modify_rdn/rename", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Net::LDAP#modify_rdn/#rename with tainted DN/newrdn — attacker can rename entries under arbitrary DNs (CWE-90)", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.net_ldap.filter.contains", Category: taint.SnkLDAP, Language: rules.LangRuby, Pattern: `Net::LDAP::Filter\.contains\s*\(`, ObjectType: "Net::LDAP::Filter", MethodName: "contains", DangerousArgs: []int{1}, Severity: rules.High, Description: "Net::LDAP::Filter.contains with tainted substring value (CWE-90)", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.net_ldap.filter.begins", Category: taint.SnkLDAP, Language: rules.LangRuby, Pattern: `Net::LDAP::Filter\.begins\s*\(`, ObjectType: "Net::LDAP::Filter", MethodName: "begins", DangerousArgs: []int{1}, Severity: rules.High, Description: "Net::LDAP::Filter.begins with tainted prefix value (CWE-90)", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.net_ldap.filter.ends", Category: taint.SnkLDAP, Language: rules.LangRuby, Pattern: `Net::LDAP::Filter\.ends\s*\(`, ObjectType: "Net::LDAP::Filter", MethodName: "ends", DangerousArgs: []int{1}, Severity: rules.High, Description: "Net::LDAP::Filter.ends with tainted suffix value (CWE-90)", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.net_ldap.filter.ex", Category: taint.SnkLDAP, Language: rules.LangRuby, Pattern: `Net::LDAP::Filter\.ex\s*\(`, ObjectType: "Net::LDAP::Filter", MethodName: "ex", DangerousArgs: []int{1}, Severity: rules.High, Description: "Net::LDAP::Filter.ex extensible match with tainted value (CWE-90)", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.net_ldap.filter.construct", Category: taint.SnkLDAP, Language: rules.LangRuby, Pattern: `Net::LDAP::Filter\.(?:construct|from_rfc2254|from_rfc4515)\s*\(`, ObjectType: "Net::LDAP::Filter", MethodName: "construct", DangerousArgs: []int{0}, Severity: rules.High, Description: "Net::LDAP::Filter.construct parses a raw filter string — attacker controls the entire filter expression (CWE-90)", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},

		// XPath injection
		{ID: "ruby.nokogiri.xpath", Category: taint.SnkXPath, Language: rules.LangRuby, Pattern: `\.xpath\s*\(|\.css\s*\(`, ObjectType: "Nokogiri::XML::Node", MethodName: "xpath/css", DangerousArgs: []int{0}, Severity: rules.High, Description: "Nokogiri XPath/CSS query with tainted expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.rexml.xpath", Category: taint.SnkXPath, Language: rules.LangRuby, Pattern: `REXML::XPath\.(?:first|each|match)\s*\(`, ObjectType: "REXML::XPath", MethodName: "first/each/match", DangerousArgs: []int{0}, Severity: rules.High, Description: "REXML XPath query with tainted expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},

		// Additional template injection
		{ID: "ruby.liquid.template.parse", Category: taint.SnkTemplate, Language: rules.LangRuby, Pattern: `Liquid::Template\.parse\s*\(`, ObjectType: "Liquid::Template", MethodName: "parse", DangerousArgs: []int{0}, Severity: rules.High, Description: "Liquid template parsing with tainted template", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.haml.engine.new", Category: taint.SnkTemplate, Language: rules.LangRuby, Pattern: `Haml::Engine\.new\s*\(`, ObjectType: "Haml::Engine", MethodName: "new", DangerousArgs: []int{0}, Severity: rules.High, Description: "Haml template rendering with tainted template", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.slim.template.new", Category: taint.SnkTemplate, Language: rules.LangRuby, Pattern: `Slim::Template\.new\s*\(`, ObjectType: "Slim::Template", MethodName: "new", DangerousArgs: []int{0}, Severity: rules.High, Description: "Slim template rendering with tainted template", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.erubi.engine.new", Category: taint.SnkTemplate, Language: rules.LangRuby, Pattern: `Erubi::Engine\.new\s*\(`, ObjectType: "Erubi::Engine", MethodName: "new", DangerousArgs: []int{0}, Severity: rules.High, Description: "Erubi template compilation with tainted template (Rails 5+ default engine, CVE-2020-8163)", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.tilt.new", Category: taint.SnkTemplate, Language: rules.LangRuby, Pattern: `Tilt\.new\s*\(`, ObjectType: "Tilt", MethodName: "new", DangerousArgs: []int{0}, Severity: rules.High, Description: "Tilt template engine instantiation with tainted path/content (SSTI)", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.tilt.template.new", Category: taint.SnkTemplate, Language: rules.LangRuby, Pattern: `Tilt::\w+Template\.new\s*\(`, ObjectType: "Tilt::Template", MethodName: "new", DangerousArgs: []int{0}, Severity: rules.High, Description: "Tilt template subclass instantiation with tainted content (SSTI)", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.mustache.render", Category: taint.SnkTemplate, Language: rules.LangRuby, Pattern: `Mustache\.render\s*\(`, ObjectType: "Mustache", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Mustache template rendering with tainted template (CVE-2022-0323)", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},

		// HTTP response header injection
		{ID: "ruby.rails.response.headers", Category: taint.SnkHeader, Language: rules.LangRuby, Pattern: `response\.headers\s*\[|response\.set_header\s*\(`, ObjectType: "ActionDispatch::Response", MethodName: "headers[]/set_header", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "HTTP response header injection via Rails response", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.sinatra.headers", Category: taint.SnkHeader, Language: rules.LangRuby, Pattern: `headers\s*\[|header\s*\(`, ObjectType: "Sinatra::Base", MethodName: "headers[]/header", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "HTTP response header injection via Sinatra", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},

		// Dynamic class instantiation
		// ObjectType "" (not "String"): constantize is a distinctive method name; a String receiver-gate
		// fails to bind when the tainted value flows through an intermediate var (name.constantize).
		{ID: "ruby.constantize", Category: taint.SnkEval, Language: rules.LangRuby, Pattern: `\.constantize`, ObjectType: "", MethodName: "constantize", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Dynamic class instantiation via constantize (RCE)", CWEID: "CWE-470", OWASPCategory: "A03:2021-Injection"},
		// const_get resolves a class/module by tainted name (CWE-470). ObjectType "" since const_get is
		// distinctive and the receiver varies (Object.const_get, klass.const_get, self.class.const_get).
		{ID: "ruby.const_get", Category: taint.SnkEval, Language: rules.LangRuby, Pattern: `\.const_get\s*\(|\bconst_get\s*\(`, ObjectType: "", MethodName: "const_get", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Dynamic class resolution via const_get (RCE / unsafe reflection)", CWEID: "CWE-470", OWASPCategory: "A03:2021-Injection"},

		// --- Reflective instance-state / method definition by tainted NAME (CWE-915 / CWE-470) ---
		// instance_variable_set/get and define_method are HELD-then-revived here on
		// the SLICE-2 PayloadArgOnly mechanism. Adding them bare false-fires on
		// idiomatic Rails, where the canonical form passes a LITERAL symbol name on
		// an internally-tainted receiver — `obj.instance_variable_set(:@count, val)`,
		// `define_method(:foo) { ... }`. The REAL danger is a tainted NAME (arg 0):
		// `obj.instance_variable_set(params[:f], v)` lets an attacker write arbitrary
		// instance state (mass assignment); `define_method(params[:m]) {...}` names a
		// method from request data (unsafe reflection). So:
		//   * DangerousArgs:[0] = the NAME/symbol arg (NOT the value), and
		//   * PayloadPosition: PayloadArgOnly — the receiver-taint fallback NEVER runs,
		//     so an incidentally-tainted receiver (idiomatic Rails internals) does not
		//     fire; only a tainted NAME does. A literal symbol name carries no source
		//     and is dropped by the dangerous-arg taint check.
		// ObjectType "" (wildcard) with a tight, call-anchored, non-wildcard Pattern
		// (no `.*`/`.+`) so weakSinkPatternOK re-validates the match against the real
		// `.method(` call shape (#1259-safe revive). Receiver-typing is unavailable
		// (any object exposes these reflection methods) and would not bind through an
		// intermediate variable anyway.
		{ID: "ruby.instance_variable_set", Category: taint.SnkEval, Language: rules.LangRuby, Pattern: `\.instance_variable_set\s*\(`, ObjectType: "", MethodName: "instance_variable_set", DangerousArgs: []int{0}, PayloadPosition: taint.PayloadArgOnly, Severity: rules.High, Description: "instance_variable_set with a tainted attribute NAME — mass assignment: a request value selects which instance variable is overwritten (privilege/state fields). A literal-symbol name on a (possibly tainted) receiver does not fire.", CWEID: "CWE-915", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
		{ID: "ruby.define_method", Category: taint.SnkEval, Language: rules.LangRuby, Pattern: `\bdefine_method\s*\(`, ObjectType: "", MethodName: "define_method", DangerousArgs: []int{0}, PayloadPosition: taint.PayloadArgOnly, Severity: rules.High, Description: "define_method with a tainted method NAME — unsafe reflection: request data names a dynamically defined method. A literal/constant method name does not fire.", CWEID: "CWE-470", OWASPCategory: "A03:2021-Injection"},
		{ID: "ruby.instance_variable_get", Category: taint.SnkEval, Language: rules.LangRuby, Pattern: `\.instance_variable_get\s*\(`, ObjectType: "", MethodName: "instance_variable_get", DangerousArgs: []int{0}, PayloadPosition: taint.PayloadArgOnly, Severity: rules.Medium, Description: "instance_variable_get with a tainted attribute NAME — a request value selects which instance variable is read (information disclosure / authorization bypass through a user-controlled key). A literal-symbol name does not fire.", CWEID: "CWE-200", OWASPCategory: "A01:2021-Broken Access Control"},

		// --- File move/copy / path construction (CWE-73) ---
		{
			ID:            "ruby.fileutils.mv",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `FileUtils\.mv\s*\(|FileUtils\.move\s*\(`,
			ObjectType:    "FileUtils",
			MethodName:    "mv/move",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "File move with potentially tainted source or destination path (external control of file name)",
			CWEID:         "CWE-73",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.fileutils.cp",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `FileUtils\.cp\s*\(|FileUtils\.copy\s*\(|FileUtils\.cp_r\s*\(`,
			ObjectType:    "FileUtils",
			MethodName:    "cp/copy/cp_r",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "File copy with potentially tainted paths (external control of file name)",
			CWEID:         "CWE-73",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.file.link",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `File\.link\s*\(`,
			ObjectType:    "File",
			MethodName:    "link",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Hard link creation with potentially tainted paths (external control of file name)",
			CWEID:         "CWE-73",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.fileutils.ln_s",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `FileUtils\.ln_s\s*\(|FileUtils\.symlink\s*\(|File\.symlink\s*\(`,
			ObjectType:    "FileUtils",
			MethodName:    "ln_s/symlink",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Symlink creation with potentially tainted paths (symlink attack)",
			CWEID:         "CWE-59",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.fileutils.mkdir_p",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `FileUtils\.mkdir_p\s*\(|Dir\.mkdir\s*\(`,
			ObjectType:    "FileUtils",
			MethodName:    "mkdir_p/Dir.mkdir",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Directory creation with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.file.rename",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `File\.rename\s*\(`,
			ObjectType:    "File",
			MethodName:    "rename",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "File rename with potentially tainted paths (external control of file name)",
			CWEID:         "CWE-73",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- ReDoS (CWE-1333) ---
		{
			ID:            "ruby.regexp.new",
			Category:      taint.SnkEval,
			Language:      rules.LangRuby,
			Pattern:       `Regexp\.new\s*\(|Regexp\.compile\s*\(`,
			ObjectType:    "Regexp",
			MethodName:    "new/compile",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Dynamic regex construction with potentially tainted pattern (ReDoS risk)",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},
		// String#match / String#match? implicitly compile a String argument
		// into a Regexp (`"foo".match(p)` ≡ `Regexp.new(p).match("foo")`), with
		// regexp metacharacters ACTIVE — unlike gsub/sub/scan/split, which match
		// a String pattern literally. So a tainted pattern argument enables
		// catastrophic backtracking in Ruby's Onigmo engine (ReDoS, CWE-1333).
		// Scoped to ObjectType "String" so DangerousArgs[0] is the *pattern*
		// (Regexp#match takes the haystack at arg 0 — the opposite — and is not
		// matched here). The haystack/receiver is never the dangerous argument.
		{
			ID:            "ruby.string.match",
			Category:      taint.SnkRegexDoS,
			Language:      rules.LangRuby,
			Pattern:       `\.match\??\s*\(`,
			ObjectType:    "String",
			MethodName:    "match/match?",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "String#match/#match? with a potentially tainted pattern — a String argument is implicitly compiled to a Regexp (metacharacters active), so an attacker-controlled pattern enables catastrophic backtracking (ReDoS). Pass user values as the haystack, never the pattern; pre-validate or anchor the regex",
			CWEID:         "CWE-1333",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Dynamic Code Evaluation (CWE-94) ---
		{
			ID:            "ruby.instance_eval",
			Category:      taint.SnkEval,
			Language:      rules.LangRuby,
			Pattern:       `instance_eval\s*\(|class_eval\s*\(|module_eval\s*\(`,
			ObjectType:    "",
			MethodName:    "instance_eval/class_eval/module_eval",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Dynamic code evaluation with potentially tainted string",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- SSRF additional (CWE-918) ---
		{
			ID:            "ruby.rest_client.get",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `RestClient\.get\s*\(|RestClient\.post\s*\(`,
			ObjectType:    "RestClient",
			MethodName:    "get/post",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "RestClient HTTP request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.excon.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `Excon\.get\s*\(|Excon\.post\s*\(|Excon\.new\s*\(`,
			ObjectType:    "Excon",
			MethodName:    "get/post/new",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Excon HTTP request with potentially tainted URL (SSRF)",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- Dir.glob with tainted pattern ---
		{
			ID:            "ruby.dir.glob",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `Dir\.glob\s*\(|Dir\[`,
			ObjectType:    "Dir",
			MethodName:    "glob/[]",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Directory glob with potentially tainted pattern (file enumeration)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- ActiveRecord additional SQL (CWE-89) ---
		{
			ID:            "ruby.activerecord.find_by_sql",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangRuby,
			Pattern:       `\.find_by_sql\s*\(`,
			ObjectType:    "",
			MethodName:    "find_by_sql",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "ActiveRecord find_by_sql with potentially tainted SQL",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Cookie injection (CWE-113) ---
		{
			ID:            "ruby.rails.cookies",
			Category:      taint.SnkHeader,
			Language:      rules.LangRuby,
			Pattern:       `cookies\[[^\]]*\]\s*=(?:[^=]|$)`,
			ObjectType:    "ActionDispatch::Cookies",
			MethodName:    "cookies[]=",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Rails cookie set with potentially tainted value",
			CWEID:         "CWE-113",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- ActiveRecord find_by_sql already exists, add connection.execute ---
		{
			ID:            "ruby.activerecord.connection.select_all",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangRuby,
			Pattern:       `connection\.select_all\s*\(|connection\.select_one\s*\(`,
			ObjectType:    "connection",
			MethodName:    "select_all/select_one",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "ActiveRecord connection select with potentially tainted SQL",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- File Read / Path Traversal (CWE-22) ---
		{
			ID:            "ruby.file.read.sink",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `File\.read\s*\(`,
			ObjectType:    "File",
			MethodName:    "read",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File read with potentially tainted path (arbitrary file read)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.file.readlines.sink",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `File\.readlines\s*\(`,
			ObjectType:    "File",
			MethodName:    "readlines",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File readlines with potentially tainted path (arbitrary file read)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.file.foreach.sink",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `File\.foreach\s*\(`,
			ObjectType:    "File",
			MethodName:    "foreach",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File foreach with potentially tainted path (line-by-line arbitrary file read)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.file.binread.sink",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `File\.binread\s*\(`,
			ObjectType:    "File",
			MethodName:    "binread",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File binary read with potentially tainted path (arbitrary file read)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.io.read.sink",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `IO\.read\s*\(`,
			ObjectType:    "IO",
			MethodName:    "IO.read",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "IO.read with potentially tainted path (arbitrary file read)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.io.readlines.sink",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `IO\.readlines\s*\(`,
			ObjectType:    "IO",
			MethodName:    "IO.readlines",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "IO.readlines with potentially tainted path (arbitrary file read)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.io.foreach.sink",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `IO\.foreach\s*\(`,
			ObjectType:    "IO",
			MethodName:    "IO.foreach",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "IO.foreach with potentially tainted path (arbitrary file read)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.io.binread.sink",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `IO\.binread\s*\(`,
			ObjectType:    "IO",
			MethodName:    "IO.binread",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "IO.binread with potentially tainted path (arbitrary file read)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.pathname.read.sink",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `Pathname\.new\s*\(.*\.read\b`,
			ObjectType:    "Pathname",
			MethodName:    "Pathname.read",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Pathname read with potentially tainted path (arbitrary file read)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.rails.send_file",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `send_file\s*\(`,
			ObjectType:    "",
			MethodName:    "send_file",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Rails send_file with potentially tainted path (arbitrary file disclosure)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- File.delete (CWE-22) ---
		{
			ID:            "ruby.file.delete",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `File\.delete\s*\(|FileUtils\.rm\s*\(|FileUtils\.rm_rf\s*\(`,
			ObjectType:    "File",
			MethodName:    "delete/rm/rm_rf",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "File deletion with potentially tainted path",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- open-uri open() SSRF (CWE-918) ---
		{
			ID:            "ruby.open_uri.open.generic",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `\bopen\s*\([^)]*#\{`,
			ObjectType:    "OpenURI",
			MethodName:    "open",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via open() with interpolated URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- Net::HTTP.get with user URL (CWE-918) ---
		{
			ID:            "ruby.net.http.post",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `Net::HTTP\.post\s*\(|Net::HTTP\.post_form\s*\(`,
			ObjectType:    "Net::HTTP",
			MethodName:    "post/post_form",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via Net::HTTP.post with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- ActionMailer mail to: (CWE-93) ---
		{
			ID:            "ruby.actionmailer.mail.to",
			Category:      taint.SnkHeader,
			Language:      rules.LangRuby,
			Pattern:       `mail\s*\(\s*to\s*:`,
			ObjectType:    "ActionMailer::Base",
			MethodName:    "mail(to:)",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ActionMailer recipient set with potentially tainted address",
			CWEID:         "CWE-93",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- ActiveRecord SQL injection via interpolation in additional methods (CWE-89) ---
		{
			ID:            "ruby.activerecord.select.interpolation",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangRuby,
			Pattern:       `\.select\s*\(\s*["'].*#\{`,
			ObjectType:    "",
			MethodName:    "select",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL injection via string interpolation in ActiveRecord .select()",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.activerecord.having.interpolation",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangRuby,
			Pattern:       `\.having\s*\(\s*["'].*#\{`,
			ObjectType:    "",
			MethodName:    "having",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL injection via string interpolation in ActiveRecord .having()",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.activerecord.joins.interpolation",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangRuby,
			Pattern:       `\.joins\s*\(\s*["'].*#\{`,
			ObjectType:    "",
			MethodName:    "joins",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL injection via string interpolation in ActiveRecord .joins()",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.activerecord.group.interpolation",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangRuby,
			Pattern:       `\.group\s*\(\s*["'].*#\{`,
			ObjectType:    "",
			MethodName:    "group",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL injection via string interpolation in ActiveRecord .group()",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.activerecord.from.interpolation",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangRuby,
			Pattern:       `\.from\s*\(\s*["'].*#\{`,
			ObjectType:    "",
			MethodName:    "from",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL injection via string interpolation in ActiveRecord .from()",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		// Remaining AR raw-SQL-accepting query builders (pluck/exists?/find_by/
		// calculate/lock). Each takes a raw SQL string fragment, so a
		// string-literal argument carrying `#{...}` interpolation or string
		// concatenation is a CWE-89 sink. ObjectType "" + an ENFORCED [^"']*
		// Pattern (no `.*`) keeps the symbol/hash/parameterized safe forms
		// (`.pluck(:name)`, `.find_by(id: v)`, `.exists?(id: v)`,
		// `.calculate(:sum, :amount)`, `.lock(true)`) from matching.
		{
			ID:            "ruby.activerecord.pluck.interpolation",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangRuby,
			Pattern:       `\.pluck\s*\(\s*(?:"[^"]*(?:#\{|"\s*\+|\+\s*")|'[^']*(?:#\{|'\s*\+|\+\s*'))`,
			ObjectType:    "",
			MethodName:    "pluck",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL injection via string interpolation/concatenation in ActiveRecord .pluck()",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.activerecord.exists.interpolation",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangRuby,
			Pattern:       `\.exists\?\s*\(\s*(?:"[^"]*(?:#\{|"\s*\+|\+\s*")|'[^']*(?:#\{|'\s*\+|\+\s*'))`,
			ObjectType:    "",
			MethodName:    "exists?",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL injection via string interpolation/concatenation in ActiveRecord .exists?()",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.activerecord.find_by.interpolation",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangRuby,
			Pattern:       `\.find_by\s*\(\s*(?:"[^"]*(?:#\{|"\s*\+|\+\s*")|'[^']*(?:#\{|'\s*\+|\+\s*'))`,
			ObjectType:    "",
			MethodName:    "find_by",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL injection via string interpolation/concatenation in ActiveRecord .find_by()",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.activerecord.calculate.interpolation",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangRuby,
			// `.calculate(:operation, "raw column #{x}")` — the SQL fragment is the
			// SECOND argument, so the Pattern scans for an interpolated/concatenated
			// string literal anywhere after `.calculate(` (it deliberately does NOT
			// anchor to the first arg), and both args 0 and 1 are checked for taint.
			Pattern:       `\.calculate\s*\([^)]*(?:"[^"]*(?:#\{|"\s*\+|\+\s*")|'[^']*(?:#\{|'\s*\+|\+\s*'))`,
			ObjectType:    "",
			MethodName:    "calculate",
			DangerousArgs: []int{0, 1},
			Severity:      rules.Critical,
			Description:   "SQL injection via string interpolation/concatenation in ActiveRecord .calculate()",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.activerecord.lock.interpolation",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangRuby,
			Pattern:       `\.lock\s*\(\s*(?:"[^"]*(?:#\{|"\s*\+|\+\s*")|'[^']*(?:#\{|'\s*\+|\+\s*'))`,
			ObjectType:    "",
			MethodName:    "lock",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "SQL injection via string interpolation/concatenation in ActiveRecord .lock() (pessimistic lock clause)",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Sequel literal SQL (CWE-89) ---
		{
			ID:            "ruby.sequel.lit",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangRuby,
			Pattern:       `Sequel\.lit\s*\(`,
			ObjectType:    "Sequel",
			MethodName:    "lit",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Sequel literal SQL string (bypasses parameterization)",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- SSRF via additional HTTP clients (CWE-918) ---
		{
			ID:            "ruby.typhoeus.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `Typhoeus\.get\s*\(|Typhoeus\.post\s*\(|Typhoeus\.put\s*\(|Typhoeus\.delete\s*\(|Typhoeus::Request\.new\s*\(`,
			ObjectType:    "Typhoeus",
			MethodName:    "get/post/put/delete/Request.new",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via Typhoeus HTTP client with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.httpclient.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `HTTPClient\.new.*\.get\s*\(|HTTPClient\.get\s*\(|HTTPClient\.post\s*\(`,
			ObjectType:    "HTTPClient",
			MethodName:    "get/post",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via HTTPClient with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.curb.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `Curl::Easy\.perform\s*\(|Curl\.get\s*\(|Curl\.post\s*\(`,
			ObjectType:    "Curl",
			MethodName:    "Easy.perform/get/post",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via Curb (libcurl binding) with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- SSRF: additional HTTP verb coverage (CWE-918) ---
		// The existing entries cover only GET for HTTParty/Faraday and GET/POST for
		// RestClient/Excon. These entries add the remaining HTTP verbs and stdlib
		// methods that are equally exploitable for SSRF.
		{
			ID:            "ruby.httparty.post_verbs",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `HTTParty\.(?:post|put|delete|patch|head)\s*\(`,
			ObjectType:    "HTTParty",
			MethodName:    "post/put/delete/patch/head",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via HTTParty HTTP methods with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.faraday.post_verbs",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `Faraday\.(?:post|put|patch|delete)\s*\(`,
			ObjectType:    "Faraday",
			MethodName:    "post/put/patch/delete",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via Faraday class-level HTTP methods with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.faraday.new",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `Faraday\.new\s*\(`,
			ObjectType:    "Faraday",
			MethodName:    "new",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via Faraday connection constructor with tainted base URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.net.http.start",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `Net::HTTP\.start\s*\(`,
			ObjectType:    "Net::HTTP",
			MethodName:    "start",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via Net::HTTP.start with tainted hostname",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.net.http.get_response",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `Net::HTTP\.get_response\s*\(`,
			ObjectType:    "Net::HTTP",
			MethodName:    "get_response",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via Net::HTTP.get_response with tainted URI",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.rest_client.put_verbs",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `RestClient\.(?:put|delete|head)\s*\(`,
			ObjectType:    "RestClient",
			MethodName:    "put/delete/head",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via RestClient HTTP methods with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.excon.put_verbs",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `Excon\.(?:put|delete|head)\s*\(`,
			ObjectType:    "Excon",
			MethodName:    "put/delete/head",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via Excon HTTP methods with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.http.get",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `(?:^|[^:\w])HTTP\.get\s*\(`,
			ObjectType:    "HTTP",
			MethodName:    "get",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via http gem HTTP.get with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.http.verbs",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `(?:^|[^:\w])HTTP\.(?:post|put|delete|patch|head)\s*\(`,
			ObjectType:    "HTTP",
			MethodName:    "post/put/delete/patch/head",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via http gem HTTP write verbs with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.http.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `(?:^|[^:\w])HTTP\.request\s*\(`,
			ObjectType:    "HTTP",
			MethodName:    "request",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "SSRF via http gem HTTP.request(verb, url) with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		// --- httpx gem: all functionality composes around the HTTPX module
		// (HTTPX.get/post/.../request). The module-level convenience methods
		// fetch a user-supplied URL → SSRF (CWE-918). Mirrors the http-gem
		// model above. ---
		{
			ID:            "ruby.httpx.get",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `(?:^|[^:\w])HTTPX\.get\s*\(`,
			ObjectType:    "HTTPX",
			MethodName:    "get",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via httpx gem HTTPX.get with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.httpx.verbs",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `(?:^|[^:\w])HTTPX\.(?:post|put|delete|patch|head)\s*\(`,
			ObjectType:    "HTTPX",
			MethodName:    "post/put/delete/patch/head",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via httpx gem HTTPX write verbs with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.httpx.request",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `(?:^|[^:\w])HTTPX\.request\s*\(`,
			ObjectType:    "HTTPX",
			MethodName:    "request",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "SSRF via httpx gem HTTPX.request(verb, url) with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.down.download",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `\bDown\.(?:download|open)\s*\(`,
			ObjectType:    "Down",
			MethodName:    "download/open",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "SSRF via Down gem Down.download/Down.open with tainted URL",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- Session trust boundary (CWE-501) ---
		{
			ID:            "ruby.session.store",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangRuby,
			Pattern:       `session\s*\[[^\]]*\]\s*=(?:[^=]|$)`,
			ObjectType:    "ActionDispatch::Session",
			MethodName:    "session[]=",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Storing tainted data in session crosses trust boundary",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "ruby.flash.store",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangRuby,
			Pattern:       `flash\s*\[[^\]]*\]\s*=(?:[^=]|$)`,
			ObjectType:    "ActionDispatch::Flash",
			MethodName:    "flash[]=",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Storing tainted data in flash crosses trust boundary (reflected in next request)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "ruby.rails.cache.write",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangRuby,
			Pattern:       `Rails\.cache\.write\s*\(`,
			ObjectType:    "ActiveSupport::Cache",
			MethodName:    "write",
			DangerousArgs: []int{1},
			Severity:      rules.Medium,
			Description:   "Storing tainted data in Rails.cache crosses trust boundary (cache poisoning)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "ruby.rails.cache.write_multi",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangRuby,
			Pattern:       `Rails\.cache\.write_multi\s*\(`,
			ObjectType:    "ActiveSupport::Cache",
			MethodName:    "write_multi",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Storing tainted data via Rails.cache.write_multi crosses trust boundary (batch cache poisoning, Rails 5.2+)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},

		// --- Background job trust boundary (CWE-501) ---
		// Enqueueing user-controlled data into a job queue crosses the trust
		// boundary: the job is serialized (JSON/Marshal) into Redis/DB, later
		// deserialized and executed by a worker process. Untrusted data in args
		// can lead to second-order injection, deserialization, SSRF, or cache
		// poisoning when the worker consumes it. Sidekiq itself warns about
		// JSON-unsafe args (Sidekiq Changes.md); ActiveJob accepts only a
		// GlobalID-safe allowlist of arg types for the same reason.
		{
			ID:            "ruby.sidekiq.perform_async",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangRuby,
			Pattern:       `\w+\.perform_async\s*\(`,
			ObjectType:    "",
			MethodName:    "perform_async",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Sidekiq job enqueue with tainted args crosses trust boundary (args serialized to Redis, re-executed later)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "ruby.sidekiq.perform_in",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangRuby,
			Pattern:       `\w+\.perform_in\s*\(`,
			ObjectType:    "",
			MethodName:    "perform_in",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Sidekiq delayed job enqueue with tainted args crosses trust boundary",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "ruby.sidekiq.perform_at",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangRuby,
			Pattern:       `\w+\.perform_at\s*\(`,
			ObjectType:    "",
			MethodName:    "perform_at",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Sidekiq scheduled job enqueue with tainted args crosses trust boundary",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "ruby.activejob.perform_later",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangRuby,
			Pattern:       `\w+\.perform_later\s*\(`,
			ObjectType:    "",
			MethodName:    "perform_later",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "ActiveJob perform_later with tainted args crosses trust boundary (args serialized via ActiveJob::Arguments into Redis/DB/SQS)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},
		{
			ID:            "ruby.resque.enqueue",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangRuby,
			Pattern:       `Resque\.enqueue(?:_in|_at|_to)?\s*\(`,
			ObjectType:    "Resque",
			MethodName:    "enqueue/enqueue_in/enqueue_at/enqueue_to",
			DangerousArgs: []int{-1},
			Severity:      rules.Medium,
			Description:   "Resque job enqueue with tainted args crosses trust boundary (args serialized to Redis as JSON, re-executed later)",
			CWEID:         "CWE-501",
			OWASPCategory: "A04:2021-Insecure Design",
		},

		// --- Redirect additional (CWE-601) ---
		{
			ID:            "ruby.sinatra.redirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangRuby,
			Pattern:       `\bredirect\s*\(`,
			ObjectType:    "",
			MethodName:    "redirect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Open redirect via Sinatra redirect()",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.rails.redirect_back",
			Category:      taint.SnkRedirect,
			Language:      rules.LangRuby,
			Pattern:       `redirect_back\s*\(`,
			ObjectType:    "",
			MethodName:    "redirect_back",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Open redirect via redirect_back with tainted fallback_location",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.rails.redirect_to.noparen",
			Category:      taint.SnkRedirect,
			Language:      rules.LangRuby,
			Pattern:       `\bredirect_to\s+[^(\s]`,
			ObjectType:    "",
			MethodName:    "redirect_to",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Open redirect via redirect_to without parentheses (idiomatic Rails, CVE-2023-22797)",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.redirect.noparen",
			Category:      taint.SnkRedirect,
			Language:      rules.LangRuby,
			Pattern:       `\bredirect\s+[^(\s]`,
			ObjectType:    "",
			MethodName:    "redirect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Open redirect via Sinatra/Grape redirect without parentheses",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.rails.redirect_back_or_to",
			Category:      taint.SnkRedirect,
			Language:      rules.LangRuby,
			Pattern:       `\bredirect_back_or_to[\s(]`,
			ObjectType:    "",
			MethodName:    "redirect_back_or_to",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Open redirect via Rails 7+ redirect_back_or_to with tainted URL",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.roda.redirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangRuby,
			Pattern:       `(?:^|[^.\w])r\.redirect[\s(]`,
			ObjectType:    "Roda::RodaRequest",
			MethodName:    "r.redirect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Open redirect via Roda request redirect",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.rack.response.redirect",
			Category:      taint.SnkRedirect,
			Language:      rules.LangRuby,
			Pattern:       `response\.redirect[\s(]`,
			ObjectType:    "Rack::Response",
			MethodName:    "response.redirect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Open redirect via Rack::Response#redirect",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.rack.location.header",
			Category:      taint.SnkRedirect,
			Language:      rules.LangRuby,
			Pattern:       `response\[['"]Location['"]\]\s*=`,
			ObjectType:    "Rack::Response",
			MethodName:    "response['Location']=",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Open redirect via direct Location header assignment in Rack response",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Weak random additional (CWE-338) ---
		{
			ID:            "ruby.crypto.random.new",
			Category:      taint.SnkCrypto,
			Language:      rules.LangRuby,
			Pattern:       `(?:^|[^.\w:])Random\.new\b|(?:^|[^.\w:])Random\.rand\s*\(`,
			ObjectType:    "Random",
			MethodName:    "Random.new/rand",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Non-cryptographic Random class for security (use SecureRandom instead)",
			CWEID:         "CWE-338",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// --- Rack response header injection (CWE-113) ---
		{
			ID:            "ruby.rack.response.set_cookie_header",
			Category:      taint.SnkHeader,
			Language:      rules.LangRuby,
			Pattern:       `Rack::Utils\.set_cookie_header\s*\(`,
			ObjectType:    "Rack::Utils",
			MethodName:    "set_cookie_header",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "HTTP response header injection via Rack response",
			CWEID:         "CWE-113",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- XSS: direct response body output (CWE-79) ---
		//
		// These sinks write directly to the HTTP response body, bypassing
		// Rails/Sinatra view-level auto-escaping. Commonly seen in Rack
		// middleware, streaming endpoints, and API controllers.
		{
			ID:            "ruby.response.write",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangRuby,
			Pattern:       `response\.write\s*\(`,
			ObjectType:    "Rack::Response",
			MethodName:    "write",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Direct response body write bypasses template escaping (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.safe_concat",
			Category:      taint.SnkHTMLOutput,
			Language:      rules.LangRuby,
			Pattern:       `\bsafe_concat\s*\(`,
			ObjectType:    "",
			MethodName:    "safe_concat",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ActionView safe_concat appends raw HTML without escaping (XSS)",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
		},
		// --- XPath/CSS injection: Nokogiri shorthand methods (CWE-643) ---
		//
		// Nokogiri's at_xpath/at_css/search are convenience aliases that
		// behave identically to xpath/css for injection purposes but use
		// different method names not caught by the existing entries.
		{
			ID:            "ruby.nokogiri.at_xpath",
			Category:      taint.SnkXPath,
			Language:      rules.LangRuby,
			Pattern:       `\.at_xpath\s*\(`,
			ObjectType:    "",
			MethodName:    "at_xpath",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Nokogiri at_xpath with tainted XPath expression (returns first match)",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.nokogiri.at_css",
			Category:      taint.SnkXPath,
			Language:      rules.LangRuby,
			Pattern:       `\.at_css\s*\(`,
			ObjectType:    "",
			MethodName:    "at_css",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Nokogiri at_css with tainted CSS selector (returns first match)",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.nokogiri.search",
			Category:      taint.SnkXPath,
			Language:      rules.LangRuby,
			Pattern:       `\.search\s*\(`,
			ObjectType:    "",
			MethodName:    "search",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Nokogiri search with tainted XPath/CSS expression",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- XPath injection: REXML Element instance methods (CWE-643) ---
		//
		// REXML's existing `ruby.rexml.xpath` entry only catches the static
		// REXML::XPath.first/each/match API. Application code far more often
		// calls XPath-accepting *instance* methods on an Element/Document
		// (get_elements, each_element) or on its Elements collection
		// (elements.delete_all). Those are the real sinks in practice.
		{
			// get_elements is REXML-specific; leave ObjectType empty so the
			// variable receiver (typically `doc` or `root`) still matches —
			// this mirrors the existing ruby.nokogiri.at_xpath convention.
			ID:            "ruby.rexml.element.get_elements",
			Category:      taint.SnkXPath,
			Language:      rules.LangRuby,
			Pattern:       `\.get_elements\s*\(`,
			ObjectType:    "",
			MethodName:    "get_elements",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "REXML Element#get_elements evaluates the given XPath against this element — tainted expression allows XPath injection",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.rexml.element.each_element",
			Category:      taint.SnkXPath,
			Language:      rules.LangRuby,
			Pattern:       `\.each_element\s*\(`,
			ObjectType:    "",
			MethodName:    "each_element",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "REXML Element#each_element iterates matches of the given XPath — tainted expression allows XPath injection",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			// .elements.delete_all on REXML collection — keep the class name so
			// matchesCatalogEntry's qualified-receiver heuristic narrows this
			// to chains ending in ".elements" and avoids matching an
			// unrelated "delete_all" (e.g., ActiveRecord::Relation#delete_all).
			ID:            "ruby.rexml.elements.delete_all",
			Category:      taint.SnkXPath,
			Language:      rules.LangRuby,
			Pattern:       `\.elements\.delete_all\s*\(`,
			ObjectType:    "REXML::Elements",
			MethodName:    "delete_all",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "REXML Elements#delete_all removes nodes matching the given XPath — tainted expression allows unbounded deletion via XPath injection",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- XPath injection: libxml-ruby (LibXML::XML::XPath) — CWE-643 ---
		//
		// libxml-ruby is the Ruby binding for libxml2. XML::XPath::Expression.new
		// compiles an XPath string (xmlXPathCompile); XML::Node#find_first
		// evaluates user-supplied expressions directly.
		{
			// Constructor-style call: the receiver is the full scope
			// `XML::XPath::Expression`. ObjectType mirrors it verbatim so the
			// direct lowercase receiver match succeeds and we don't fire on
			// every `.new(` call in the program.
			ID:            "ruby.libxml.xpath.expression.new",
			Category:      taint.SnkXPath,
			Language:      rules.LangRuby,
			Pattern:       `XML::XPath::Expression\.new\s*\(`,
			ObjectType:    "XML::XPath::Expression",
			MethodName:    "Expression.new",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "libxml-ruby XML::XPath::Expression.new compiles a user-supplied XPath string — tainted expression allows XPath injection",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			// find_first is essentially unique to libxml-ruby among common
			// Ruby libraries; ObjectType empty is safe and matches the
			// existing ruby.nokogiri.search / .at_xpath convention.
			ID:            "ruby.libxml.node.find_first",
			Category:      taint.SnkXPath,
			Language:      rules.LangRuby,
			Pattern:       `\.find_first\s*\(`,
			ObjectType:    "",
			MethodName:    "find_first",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "libxml-ruby XML::Node#find_first evaluates the given XPath on the document — tainted expression allows XPath injection",
			CWEID:         "CWE-643",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Weak ciphers: Blowfish and RC2 (CWE-327) ---
		//
		// Blowfish (BF) has a 64-bit block size vulnerable to SWEET32
		// (CVE-2016-2183). RC2 has an effective key size that can be
		// reduced. Both are deprecated in favor of AES-128/256-GCM.
		{
			ID:            "ruby.crypto.openssl.blowfish",
			Category:      taint.SnkCrypto,
			Language:      rules.LangRuby,
			Pattern:       `OpenSSL::Cipher\.new\s*\(\s*['"](?:BF|bf|Blowfish|blowfish)`,
			ObjectType:    "OpenSSL::Cipher",
			MethodName:    "Cipher.new",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Weak Blowfish cipher (64-bit block, SWEET32 vulnerable, use AES-GCM)",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "ruby.crypto.openssl.rc2",
			Category:      taint.SnkCrypto,
			Language:      rules.LangRuby,
			Pattern:       `OpenSSL::Cipher\.new\s*\(\s*['"](?:RC2|rc2)`,
			ObjectType:    "OpenSSL::Cipher",
			MethodName:    "Cipher.new",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Weak RC2 cipher (reducible key strength, use AES-GCM)",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},

		// --- JWT signature-verification bypass (CWE-347) ---
		//
		// Parsing a JWT without verifying its HMAC/RSA signature leaves all
		// claims attacker-controlled. The three Ruby libraries most often
		// involved are jose-ruby (JOSE::JWT.peek_*), ruby-jwt v3
		// (JWT::EncodedToken#unverified_payload), and — historically —
		// json-jwt. Each sink below is unsafe-by-design: it returns decoded
		// claims/header without checking the signature. Safe flows use the
		// paired sanitizers in ruby_sanitizers.go (verify / verify_strict /
		// verify_signature! / encode / sign!).
		{
			ID:            "ruby.jose.jwt.peek_payload",
			Category:      taint.SnkCrypto,
			Language:      rules.LangRuby,
			Pattern:       `JOSE::JWT\.peek_payload\s*\(`,
			ObjectType:    "JOSE::JWT",
			MethodName:    "peek_payload",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "jose-ruby JOSE::JWT.peek_payload returns the JWT payload without verifying the signature — attacker-controlled claims (CWE-347)",
			CWEID:         "CWE-347",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "ruby.jose.jwt.peek_protected",
			Category:      taint.SnkCrypto,
			Language:      rules.LangRuby,
			Pattern:       `JOSE::JWT\.peek_protected\s*\(`,
			ObjectType:    "JOSE::JWT",
			MethodName:    "peek_protected",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "jose-ruby JOSE::JWT.peek_protected reads the JOSE header (alg, typ) without verification; trusting the attacker-supplied alg enables algorithm-confusion attacks — use JOSE::JWT.verify_strict instead",
			CWEID:         "CWE-347",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		{
			ID:            "ruby.jwt.encoded_token.unverified_payload",
			Category:      taint.SnkCrypto,
			Language:      rules.LangRuby,
			Pattern:       `\.unverified_payload\b`,
			ObjectType:    "JWT::EncodedToken",
			MethodName:    "unverified_payload",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "ruby-jwt v3 JWT::EncodedToken#unverified_payload returns the payload without signature verification; call verify_signature!/verify! first and use .payload instead",
			CWEID:         "CWE-347",
			OWASPCategory: "A02:2021-Cryptographic Failures",
		},
		// ── MongoDB NoSQL injection — mongo ruby driver (CWE-943) ─────
		// Mongo::Collection filter/update documents built from untrusted
		// input enable NoSQL operator injection ($ne, $gt, $regex, $where)
		// that bypasses authentication or exfiltrates records. Method
		// names below are MongoDB-specific and do not collide with
		// ActiveRecord/Sequel query APIs.
		// https://mongodb.com/docs/ruby-driver/current/reference/crud-operations/
		{
			ID:            "ruby.mongo.collection.find_one",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.find_one\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "find_one",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Mongo::Collection#find_one with user-controlled filter enables NoSQL operator injection (e.g., auth bypass via { password: { '$ne' => '' } })",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.find_one_and_update",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.find_one_and_update\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "find_one_and_update",
			DangerousArgs: []int{0, 1},
			Severity:      rules.Critical,
			Description:   "Mongo::Collection#find_one_and_update with user-controlled filter or update document (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.find_one_and_replace",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.find_one_and_replace\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "find_one_and_replace",
			DangerousArgs: []int{0, 1},
			Severity:      rules.Critical,
			Description:   "Mongo::Collection#find_one_and_replace with user-controlled filter or replacement document (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.find_one_and_delete",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.find_one_and_delete\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "find_one_and_delete",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Mongo::Collection#find_one_and_delete with user-controlled filter — NoSQL injection can delete unintended records",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.update_one",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.update_one\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "update_one",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Mongo::Collection#update_one with user-controlled filter or update document (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.update_many",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.update_many\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "update_many",
			DangerousArgs: []int{0, 1},
			Severity:      rules.Critical,
			Description:   "Mongo::Collection#update_many with user-controlled filter — NoSQL injection can modify multiple records at once",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.replace_one",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.replace_one\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "replace_one",
			DangerousArgs: []int{0, 1},
			Severity:      rules.Critical,
			Description:   "Mongo::Collection#replace_one with user-controlled filter or replacement document (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.delete_one",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.delete_one\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "delete_one",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Mongo::Collection#delete_one with user-controlled filter (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.delete_many",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.delete_many\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "delete_many",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Mongo::Collection#delete_many with user-controlled filter — NoSQL injection can mass-delete records (e.g., {} matches all)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.insert_one",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.insert_one\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "insert_one",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Mongo::Collection#insert_one with user-controlled document — attacker-controlled operators/fields can overwrite privileged attributes (mass-assignment)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.bulk_write",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.bulk_write\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "bulk_write",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Mongo::Collection#bulk_write with user-controlled requests — NoSQL injection across multiple operations",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.aggregate",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.aggregate\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "aggregate",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Mongo::Collection#aggregate with user-controlled pipeline — attacker can inject stages ($lookup, $out, $merge) to exfiltrate data or overwrite collections",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.count_documents",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.count_documents\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "count_documents",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Mongo::Collection#count_documents with user-controlled filter — NoSQL operator injection enables record enumeration / blind exfiltration",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		// --- Mongo collection NoSQL sinks (CWE-943 / CWE-94) — newer SnkNoSQL category ---
		// Tagged as SnkNoSQL (added 2026-04-30 via PR #639) to disambiguate from
		// SQL injection. Coverage gap: the find/distinct/watch/map_reduce APIs
		// aren't covered by the older entries above. ObjectType "Mongo::Collection"
		// scopes to receivers like `coll`, `collection`, `col` (lastPart abbreviation
		// match) — class-name receivers (`User.find`) won't trip it.
		{
			ID:            "ruby.mongo.collection.find",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.find\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "find",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Mongo::Collection#find with user-controlled filter — NoSQL operator injection ($ne, $regex, $where) enables auth bypass and bulk record exfiltration",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.distinct",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.distinct\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "distinct",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "Mongo::Collection#distinct(field, filter) with user-controlled filter — NoSQL operator injection lets attacker enumerate values across documents outside the intended scope",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.watch",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.watch\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "watch",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Mongo::Collection#watch with user-controlled change-stream pipeline — attacker-injected stages ($lookup, $project) leak data from other collections",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongo.collection.map_reduce",
			Category:      taint.SnkEval,
			Language:      rules.LangRuby,
			Pattern:       `\.map_reduce\s*\(`,
			ObjectType:    "Mongo::Collection",
			MethodName:    "map_reduce",
			DangerousArgs: []int{0, 1},
			Severity:      rules.Critical,
			Description:   "Mongo::Collection#map_reduce(map_js, reduce_js) — both args are JavaScript executed server-side; tainted code yields RCE within the mongod JS engine (CWE-94)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		// --- Archive extraction sinks (Zip Slip / Tar Slip, CWE-22) ---
		// Extracting archives without validating entry paths allows attackers
		// to write outside the intended destination via "../" entry names
		// (Snyk Zip Slip, CVE-2019-16892 for rubyzip; similar for minitar).
		// Fix by checking File.expand_path(entry.name, dest).start_with?(dest)
		// before extraction, or by using File.basename to strip directories.
		{
			ID:            "ruby.rubyzip.entry.extract",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `\.extract\s*\(`,
			ObjectType:    "Zip::Entry",
			MethodName:    "extract",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Rubyzip Zip::Entry#extract with tainted destination path (Zip Slip, CVE-2019-16892)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.minitar.unpack",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `Minitar\.unpack\s*\(`,
			ObjectType:    "Archive::Tar::Minitar",
			MethodName:    "unpack",
			DangerousArgs: []int{1},
			Severity:      rules.High,
			Description:   "Archive::Tar::Minitar.unpack with tainted destination (Tar Slip)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.rubyzip.inputstream.open",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `Zip::InputStream\.open\s*\(`,
			ObjectType:    "Zip::InputStream",
			MethodName:    "open",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Rubyzip Zip::InputStream.open with tainted archive path (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Image processing: MiniMagick / RMagick command injection (CWE-78) ---
		// MiniMagick wraps the ImageMagick CLI (convert, mogrify, identify). Tainted
		// filenames/URLs reach Kernel#open and the shell, enabling RCE via the
		// "|command" trick (CVE-2019-13574). RMagick uses ImageMagick's C library
		// directly but processes user-supplied image data — historically exploitable
		// via malicious SVG/MVG coders ("ImageTragick", CVE-2016-3714 family).
		{
			ID:            "ruby.minimagick.image.open",
			Category:      taint.SnkCommand,
			Language:      rules.LangRuby,
			Pattern:       `MiniMagick::Image\.open\s*\(`,
			ObjectType:    "MiniMagick::Image",
			MethodName:    "open",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "MiniMagick::Image.open with tainted path/URL — Kernel#open accepts '|cmd' for RCE (CVE-2019-13574)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.minimagick.image.new",
			Category:      taint.SnkCommand,
			Language:      rules.LangRuby,
			Pattern:       `MiniMagick::Image\.new\s*\(`,
			ObjectType:    "MiniMagick::Image",
			MethodName:    "new",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MiniMagick::Image.new with tainted path — path is handed to ImageMagick CLI (identify) for format probing",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.minimagick.image.read",
			Category:      taint.SnkCommand,
			Language:      rules.LangRuby,
			Pattern:       `MiniMagick::Image\.read\s*\(`,
			ObjectType:    "MiniMagick::Image",
			MethodName:    "read",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "MiniMagick::Image.read with tainted image data piped to ImageMagick CLI — exploitable via malicious SVG/MVG coders",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.rmagick.image.read",
			Category:      taint.SnkCommand,
			Language:      rules.LangRuby,
			Pattern:       `Magick::Image\.read\s*\(`,
			ObjectType:    "Magick::Image",
			MethodName:    "read",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "RMagick Magick::Image.read with tainted path — ImageTragick RCE via malicious SVG/MVG/PDF delegates (CVE-2016-3714)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.rmagick.image.ping",
			Category:      taint.SnkCommand,
			Language:      rules.LangRuby,
			Pattern:       `Magick::Image\.ping\s*\(`,
			ObjectType:    "Magick::Image",
			MethodName:    "ping",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "RMagick Magick::Image.ping with tainted path — still invokes image coders (ImageTragick exposure)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.rmagick.image.from_blob",
			Category:      taint.SnkCommand,
			Language:      rules.LangRuby,
			Pattern:       `Magick::Image\.from_blob\s*\(`,
			ObjectType:    "Magick::Image",
			MethodName:    "from_blob",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "RMagick Magick::Image.from_blob with tainted image bytes — ImageTragick RCE via SVG/MVG coders",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.rmagick.image.read_inline",
			Category:      taint.SnkCommand,
			Language:      rules.LangRuby,
			Pattern:       `Magick::Image\.read_inline\s*\(`,
			ObjectType:    "Magick::Image",
			MethodName:    "read_inline",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "RMagick Magick::Image.read_inline with tainted base64 — processes image via coders (ImageTragick exposure)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.rmagick.imagelist.new",
			Category:      taint.SnkCommand,
			Language:      rules.LangRuby,
			Pattern:       `Magick::ImageList\.new\s*\(`,
			ObjectType:    "Magick::ImageList",
			MethodName:    "new",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "RMagick Magick::ImageList.new with tainted paths — splat args read via ImageMagick coders (ImageTragick)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Neo4j Cypher injection (CWE-943) ---
		// Building a Cypher query string from user input via interpolation lets
		// an attacker alter MATCH/CREATE/DELETE semantics or append clauses.
		// Safe code passes user values via a parameters hash — e.g.
		//   driver.execute_query("MATCH (n) WHERE n.name = $name RETURN n", name: user_input)
		// https://neo4j.com/developer/kb/protecting-against-cypher-injection/
		// Note: `session.run` / `tx.run` are NOT added here because the bare
		// method name "run" collides with Sequel's `DB.run` SQL sink and would
		// over-match other Ruby libraries using `run`.
		{
			ID:            "ruby.neo4j.active_base.run_query",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `Neo4j::ActiveBase\.run_query\s*\(`,
			ObjectType:    "",
			MethodName:    "run_query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Neo4j::ActiveBase.run_query with tainted Cypher (Cypher injection); pass user values via a params hash instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.active_graph.base.query",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `ActiveGraph::Base\.query\s*\(`,
			ObjectType:    "ActiveGraph::Base",
			MethodName:    "query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "ActiveGraph::Base.query with tainted Cypher (Cypher injection); pass user values via a params hash instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.neo4j.driver.execute_query",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `(?:driver|neo4j_driver|async_driver)\.execute_query\s*\(`,
			ObjectType:    "Neo4j::Driver",
			MethodName:    "execute_query",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Neo4j Driver#execute_query (v5+ unified API) with tainted Cypher (Cypher injection); pass user values via the params hash arg instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// Apache Cassandra (DataStax cassandra-driver gem) — CQL injection (CWE-943).
		// The Ruby driver exposes a Cassandra::Session built from a connected
		// cluster (`session = cluster.connect(keyspace)`). #execute / #execute_async
		// accept a CQL string as their first arg; safe code passes user values
		// via the :arguments option, e.g.
		//   session.execute("SELECT * FROM users WHERE id = ?", arguments: [id])
		// Interpolating user input directly into the CQL string is exploitable.
		// #prepare / #prepare_async take the CQL body of a prepared statement
		// — interpolating user input into that body bypasses the subsequent
		// parameter binding done at #bind / #execute time.
		// Cassandra::Statements::Simple.new wraps a raw CQL string into a
		// Simple statement; values must travel via the params arg, not the cql.
		// http://datastax.github.io/ruby-driver/api/cassandra/session/
		{
			ID:            "ruby.cassandra.session.execute",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `(?:session|cassandra_session|cluster_session|cas_session)\.execute\s*\(`,
			ObjectType:    "Cassandra::Session",
			MethodName:    "execute",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DataStax Cassandra Session#execute with tainted CQL string enables CQL injection; pass user values via the :arguments option instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.cassandra.session.execute_async",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `(?:session|cassandra_session|cluster_session|cas_session)\.execute_async\s*\(`,
			ObjectType:    "Cassandra::Session",
			MethodName:    "execute_async",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DataStax Cassandra Session#execute_async with tainted CQL string enables CQL injection; pass user values via the :arguments option instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.cassandra.session.prepare",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `(?:session|cassandra_session|cluster_session|cas_session)\.prepare\s*\(`,
			ObjectType:    "Cassandra::Session",
			MethodName:    "prepare",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DataStax Cassandra Session#prepare with tainted CQL — interpolating user input into the prepared statement body bypasses the subsequent parameter binding",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.cassandra.session.prepare_async",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `(?:session|cassandra_session|cluster_session|cas_session)\.prepare_async\s*\(`,
			ObjectType:    "Cassandra::Session",
			MethodName:    "prepare_async",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "DataStax Cassandra Session#prepare_async with tainted CQL — interpolating user input into the prepared statement body bypasses the subsequent parameter binding",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.cassandra.statements.simple.new",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `Cassandra::Statements::Simple\.new\s*\(`,
			ObjectType:    "Cassandra::Statements::Simple",
			MethodName:    "new",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Cassandra::Statements::Simple.new seeded with tainted CQL string is injectable; pass user values via the params arg instead",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// Elasticsearch / OpenSearch (elasticsearch-ruby + opensearch-ruby)
		// Mirrors py.elasticsearch.* (PR #422), js.elasticsearch.* (PR #457),
		// java.elasticsearch.* (PR #436), php.elasticsearch.* (PR #438),
		// go.elasticsearch.* (PR #454), kotlin.elasticsearch.* (PR #464),
		// groovy.elasticsearch.* (PR #469), perl.elasticsearch.* (PR #467).
		// Only ES/OS-UNIQUE method names are catalogued. Generic verbs like
		// .search()/.index()/.update()/.get()/.bulk() are deliberately
		// excluded — they collide with ActiveRecord/Sidekiq/Mongo/Nokogiri
		// in real Ruby code, and ObjectType-based scoping is unreliable in
		// the tsflow matcher (e.g. receiver "es" is not a prefix of
		// "Elasticsearch::Client" so the natural variable name fails the
		// abbreviation heuristic). The names below have no other catalog
		// owner in ruby_*.go (verified) and no production Ruby gem in wide
		// use exposes them, so empty ObjectType is safe.
		// Refs: https://github.com/elastic/elasticsearch-ruby
		//       https://github.com/opensearch-project/opensearch-ruby
		//       https://www.elastic.co/guide/en/elasticsearch/painless/current/painless-execute-api.html
		{
			ID:            "ruby.elasticsearch.msearch",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.msearch\s*\(`,
			ObjectType:    "",
			MethodName:    "msearch",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Elasticsearch/OpenSearch Ruby client #msearch with tainted body — multi-search NDJSON DSL injection across queries; per-shard cross-index data exfiltration (CWE-943)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.elasticsearch.delete_by_query",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.delete_by_query\s*\(`,
			ObjectType:    "",
			MethodName:    "delete_by_query",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch/OpenSearch Ruby client #delete_by_query with tainted DSL body — destructive bulk-delete; injection deletes documents outside intended scope (CWE-943)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.elasticsearch.update_by_query",
			Category:      taint.SnkEval,
			Language:      rules.LangRuby,
			Pattern:       `\.update_by_query\s*\(`,
			ObjectType:    "",
			MethodName:    "update_by_query",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch/OpenSearch Ruby client #update_by_query — body accepts a Painless 'script' field; tainted script source = arbitrary code execution on the cluster, plus DSL injection on the query selector (CWE-94/CWE-943)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.elasticsearch.scripts_painless_execute",
			Category:      taint.SnkEval,
			Language:      rules.LangRuby,
			Pattern:       `\.scripts_painless_execute\s*\(`,
			ObjectType:    "",
			MethodName:    "scripts_painless_execute",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch/OpenSearch Ruby client #scripts_painless_execute — direct Painless code execution on the cluster (CWE-94)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.elasticsearch.put_script",
			Category:      taint.SnkEval,
			Language:      rules.LangRuby,
			Pattern:       `\.put_script\s*\(`,
			ObjectType:    "",
			MethodName:    "put_script",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch/OpenSearch Ruby client #put_script stores a tainted Painless script — every later invocation executes attacker-supplied code on the cluster (persistent RCE) (CWE-94)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.elasticsearch.reindex",
			Category:      taint.SnkEval,
			Language:      rules.LangRuby,
			Pattern:       `\.reindex\s*\(`,
			ObjectType:    "",
			MethodName:    "reindex",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "Elasticsearch/OpenSearch Ruby client #reindex — body accepts a Painless 'script' field plus source/dest selectors and a remote 'host' field; tainted body enables RCE, DSL injection, and SSRF to attacker-chosen remote clusters (CWE-94)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.elasticsearch.search_template",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.search_template\s*\(`,
			ObjectType:    "",
			MethodName:    "search_template",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Elasticsearch/OpenSearch Ruby client #search_template — body accepts an inline Mustache template ('source') rendered server-side then run as a query DSL; tainted template permits Mustache+DSL injection over fields/filters (CWE-943)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// Net::SSH / Net::SCP / Net::SFTP — remote command execution and remote file
		// operations (net-ssh, net-scp, net-sftp gems; the SSH transport that
		// Capistrano, SSHKit and Mina build on). Tainted command strings reach a
		// shell on the remote host; tainted remote/local paths are path traversal.
		{
			ID:            "ruby.net_ssh.exec_bang",
			Category:      taint.SnkCommand,
			Language:      rules.LangRuby,
			Pattern:       `\.exec!\s*\(`,
			ObjectType:    "Net::SSH",
			MethodName:    "exec!",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Net::SSH::Connection::Session#exec! runs its argument as a command line in a shell on the remote host; interpolating user input enables OS command injection on that host",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.net_scp.upload_bang",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `\.upload!\s*\(`,
			ObjectType:    "Net::SCP",
			MethodName:    "upload!",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Net::SCP#upload! — arg 0 is the local path read and shipped to the remote, arg 1 is the remote destination path; tainted paths permit reading/writing arbitrary files (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.net_scp.download_bang",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `\.download!\s*\(`,
			ObjectType:    "Net::SCP",
			MethodName:    "download!",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Net::SCP#download! — arg 0 is the remote path read, arg 1 is the local destination path; tainted paths permit reading arbitrary remote files and writing arbitrary local files (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.net_sftp.download_bang",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `\.download!\s*\(`,
			ObjectType:    "Net::SFTP",
			MethodName:    "download!",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Net::SFTP::Session#download! — arg 0 is the remote path read, arg 1 is the local destination path; tainted paths permit reading arbitrary remote files and writing arbitrary local files (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.net_sftp.upload_bang",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `\.upload!\s*\(`,
			ObjectType:    "Net::SFTP",
			MethodName:    "upload!",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Net::SFTP::Session#upload! — arg 0 is the local path read, arg 1 is the remote destination path; tainted paths permit reading arbitrary local files and writing arbitrary remote files (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.net_sftp.remove_bang",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `\.remove!\s*\(`,
			ObjectType:    "Net::SFTP",
			MethodName:    "remove!",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Net::SFTP::Session#remove! deletes the file at the given remote path; a tainted path lets an attacker delete arbitrary files on the remote host (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.net_sftp.rename_bang",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `\.rename!\s*\(`,
			ObjectType:    "Net::SFTP",
			MethodName:    "rename!",
			DangerousArgs: []int{0, 1},
			Severity:      rules.High,
			Description:   "Net::SFTP::Session#rename! moves a file between two remote paths; tainted source/destination paths permit arbitrary file movement on the remote host (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.net_sftp.mkdir_bang",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `\.mkdir!\s*\(`,
			ObjectType:    "Net::SFTP",
			MethodName:    "mkdir!",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Net::SFTP::Session#mkdir! creates a directory at the given remote path; a tainted path lets an attacker create directories anywhere on the remote host (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
		{
			ID:            "ruby.net_sftp.open_bang",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangRuby,
			Pattern:       `\.open!\s*\(`,
			ObjectType:    "Net::SFTP",
			MethodName:    "open!",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Net::SFTP::Session#open! opens (and may create/truncate) the file at the given remote path; a tainted path is arbitrary remote file read/write (path traversal)",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// ── Mongoid ODM (MongoDB) NoSQL injection (CWE-943 / CWE-94) ──
		// Mongoid is the high-level MongoDB ODM (Model < Mongoid::Document)
		// layered over the raw `mongo` driver covered above. Its Criteria
		// query API is distinct from the Mongo::Collection sinks: queries are
		// built on the model class / relation (`User.where(...)`) and return a
		// Mongoid::Criteria. Two injection shapes matter:
		//   1. Operator injection — a tainted Hash flows into a filter and an
		//      attacker smuggles a query operator, e.g. params[:auth] arriving
		//      as {"$ne" => nil} turns `User.where(token: params[:auth])` into
		//      an auth bypass. We flag the string-interpolation form of .where
		//      (ObjectType-scoped to Mongoid::Criteria so it is distinct from
		//      the identical ActiveRecord/Sequel .where interpolation sinks).
		//   2. Server-side JavaScript — `$where` / Criteria#for_js evaluate a
		//      JS expression inside mongod; tainted source is RCE in the JS
		//      engine (same class as Mongo::Collection#map_reduce). Tagged
		//      SnkEval/CWE-94 to mirror that precedent.
		// Refs: mongoid.org/docs (Queries — JavaScript) ; CWE-943.
		{
			ID:            "ruby.mongoid.criteria.where.interpolation",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangRuby,
			Pattern:       `\.where\s*\(\s*["'][^"']*#\{`,
			ObjectType:    "Mongoid::Criteria",
			MethodName:    "where",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Mongoid Criteria#where with a string-interpolated filter — user input concatenated into the Mongo query selector permits operator/JS injection (NoSQL injection)",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongoid.criteria.where.js",
			Category:      taint.SnkEval,
			Language:      rules.LangRuby,
			Pattern:       `\.where\s*\(\s*["']?\$where["']?\s*(?:=>|:)`,
			ObjectType:    "Mongoid::Criteria",
			MethodName:    "where($where)",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Mongoid Criteria#where with a $where operator — its value is a JavaScript expression evaluated server-side by mongod; tainted source is RCE in the JS engine (CWE-94)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.mongoid.criteria.for_js",
			Category:      taint.SnkEval,
			Language:      rules.LangRuby,
			Pattern:       `\.for_js\s*\(`,
			ObjectType:    "Mongoid::Criteria",
			MethodName:    "for_js",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "Mongoid Criteria#for_js(js) runs a JavaScript expression server-side via the $where operator; a tainted expression is RCE inside the mongod JS engine (CWE-94)",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},

		// ── ReDoS on untrusted regex pattern (CWE-1333) ──
		// The existing ruby.regexp.new sink flags bare Regexp.new/Regexp.compile
		// (SnkEval). This entry covers the distinct *dynamic-match* shape — a
		// pattern compiled from user input AND immediately matched (=~ / #match /
		// #match?) — which is the canonical catastrophic-backtracking ReDoS form.
		// Scoped to an inline Regexp.new(...) on the match operator so literal
		// regexes (str =~ /static/, name.match(/[a-z]+/)) never trip it.
		{
			ID:            "ruby.regexp.dynamic_match",
			Category:      taint.SnkRegexDoS,
			Language:      rules.LangRuby,
			Pattern:       `(?:=~|\.match\??)\s*\(?\s*Regexp\.new\s*\(`,
			ObjectType:    "Regexp",
			MethodName:    "=~/match(Regexp.new)",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Matching against a Regexp compiled from untrusted input (=~ / String#match(Regexp.new(...))) — an attacker-controlled pattern enables catastrophic backtracking (ReDoS)",
			CWEID:         "CWE-1333",
			OWASPCategory: "A05:2021-Security Misconfiguration",
		},

		// ── Mass assignment (CWE-915) ──
		// Writing an unfiltered request hash directly into a model's attributes
		// lets an attacker set columns the form never exposed (is_admin, role,
		// account_id …). ActiveRecord's assign_attributes/update_attributes take
		// an attribute hash as their first arg, so a tainted `params` (or a
		// `params.permit!`-blessed hash) flowing in is the classic Rails
		// mass-assignment vuln. permit! itself disables strong-parameter
		// filtering, marking the whole hash permitted — a distinctive bang call.
		// Narrowly anchored to the bang/permit method names so ordinary
		// attribute reads and unrelated #update calls (Redis/Mongo/Sequel) don't
		// trip. The safe form is params.permit(:title, :body) with an explicit
		// allowlist.
		{
			ID:            "ruby.activerecord.assign_attributes",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangRuby,
			Pattern:       `\.assign_attributes\s*\(`,
			ObjectType:    "ActiveRecord::Base",
			MethodName:    "assign_attributes",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ActiveRecord#assign_attributes with an unfiltered params hash — attacker can set attributes the form never exposed (mass assignment); use strong parameters params.permit(:allowed, ...)",
			CWEID:         "CWE-915",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},
		{
			ID:            "ruby.activerecord.update_attributes",
			Category:      taint.SnkTrustBoundary,
			Language:      rules.LangRuby,
			Pattern:       `\.update_attributes!?\s*\(`,
			ObjectType:    "ActiveRecord::Base",
			MethodName:    "update_attributes",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "ActiveRecord#update_attributes(!) with an unfiltered params hash — mass assignment of unexposed attributes; use strong parameters params.permit(:allowed, ...)",
			CWEID:         "CWE-915",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// --- Padrino framework (Sinatra-based full-stack) ---
		// Padrino exposes Sinatra/Tilt shorthand renderers as bare route-block
		// calls. When the template name/path is attacker-controlled (e.g.
		// `erb params[:tpl]`, `haml tmpl`), the resolved template is rendered
		// server-side — server-side template injection / template path
		// traversal. Symbol/string literals (the safe idiom `erb :index`) are
		// never tainted, so the DangerousArgs taint gate keeps those clean.
		//
		// NOTE: a bare `render <var>` sink is deliberately NOT modelled — the
		// method name `render` collides with Rails' keyword-argument render
		// forms (`render json:`, `render plain:`, `render inline:`), which the
		// AST walker cannot distinguish from a template-name argument, so it
		// would false-positive on idiomatic Rails. The engine-distinct
		// Sinatra/Padrino/Tilt renderers below (erb/haml/slim/liquid/partial)
		// have no such collision.
		{
			ID:            "ruby.padrino.erb",
			Category:      taint.SnkTemplate,
			Language:      rules.LangRuby,
			Pattern:       `\berb\s+[a-z_]\w*(?:\b[^:\w]|$)`,
			ObjectType:    "",
			MethodName:    "erb",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Padrino/Sinatra erb shorthand renderer with a tainted template name — SSTI / template path traversal; pass a fixed symbol literal (erb :view)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.padrino.haml",
			Category:      taint.SnkTemplate,
			Language:      rules.LangRuby,
			Pattern:       `\bhaml\s+[a-z_]\w*(?:\b[^:\w]|$)`,
			ObjectType:    "",
			MethodName:    "haml",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Padrino/Sinatra haml shorthand renderer with a tainted template name — SSTI / template path traversal; pass a fixed symbol literal (haml :view)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.padrino.slim",
			Category:      taint.SnkTemplate,
			Language:      rules.LangRuby,
			Pattern:       `\bslim\s+[a-z_]\w*(?:\b[^:\w]|$)`,
			ObjectType:    "",
			MethodName:    "slim",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Padrino/Sinatra slim shorthand renderer with a tainted template name — SSTI / template path traversal; pass a fixed symbol literal (slim :view)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.padrino.liquid",
			Category:      taint.SnkTemplate,
			Language:      rules.LangRuby,
			Pattern:       `\bliquid\s+[a-z_]\w*(?:\b[^:\w]|$)`,
			ObjectType:    "",
			MethodName:    "liquid",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Padrino/Sinatra liquid shorthand renderer with a tainted template name — SSTI / template path traversal; pass a fixed symbol literal (liquid :view)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.padrino.partial",
			Category:      taint.SnkTemplate,
			Language:      rules.LangRuby,
			Pattern:       `\bpartial\s+[a-z_]\w*(?:\b[^:\w]|$)`,
			ObjectType:    "",
			MethodName:    "partial",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Padrino partial helper with a tainted template name — server-side template injection (SSTI); pass a fixed symbol literal (partial :item)",
			CWEID:         "CWE-1336",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "ruby.padrino.send_file",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `\bsend_file\s+[a-z_]\w*(?:\b[^:\w]|$)`,
			ObjectType:    "",
			MethodName:    "send_file",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Padrino/Sinatra send_file with a tainted path (no parentheses) — arbitrary file disclosure / path traversal; constrain to a fixed directory and File.basename the user portion",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// ─────────────────────────────────────────────────────────────────
		// ECL wave-2 (ecl2/ruby): closing the last coverage-breadth gaps.
		// Every entry below is ObjectType-anchored (JSON / Net::FTP / @global
		// bare-call) so it cannot collide with same-named methods on unrelated
		// receivers, and gated by taint reaching the dangerous argument.
		//
		// HELD (real-repo A/B proved these FP on Discourse/GitLab and CANNOT be
		// expressed precisely without an engine change — a missing detection
		// beats a false positive):
		//   • ActiveRecord update_all/calculate/sum/average/min/max/lock raw-SQL
		//     fragments — tsflow keys on method-name + ANY arg/receiver taint and
		//     does not consult the catalog Pattern, so (a) it cannot tell the
		//     dangerous raw-String form from the safe Hash/symbol/boolean form,
		//     and (b) it fires whenever the *receiver* (an AR relation) is tainted
		//     even though the column/clause arg is a fixed literal. It also can't
		//     distinguish AR's #sum/#lock from Enumerable#sum (rows.sum(&:count))
		//     or PostLocker#lock. All flagged only safe code on Discourse.
		//   • instance_variable_set / instance_variable_get / define_method — the
		//     danger is a tainted NAME arg, but tsflow fires on a tainted receiver
		//     (e.g. params.instance_variable_set(:@literal, v)) which is idiomatic
		//     Rails-internals code, not a vuln.
		// The AR raw-SQL escape hatches that ARE precisely modelled
		// (find_by_sql / execute / exec_query / raw-driver query) already cover
		// the genuinely-exploitable surface.

		// --- JSON.load unsafe deserialization (CWE-502) ---
		// JSON.load (NOT JSON.parse) honours the `create_additions` option,
		// which lets serialized "json_class" hints instantiate arbitrary
		// Ruby objects via their .json_create hook — an object-injection /
		// RCE-gadget vector on untrusted input. Paired sanitizer:
		// ruby.json.parse (JSON.parse never instantiates objects).
		{
			ID:            "ruby.json.load",
			Category:      taint.SnkDeserialize,
			Language:      rules.LangRuby,
			Pattern:       `JSON\.load\s*\(`,
			ObjectType:    "JSON",
			MethodName:    "load",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "JSON.load on untrusted input — unlike JSON.parse it processes the create_additions/json_class mechanism, instantiating arbitrary Ruby objects from the payload (object injection / deserialization gadget). Use JSON.parse for untrusted data",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		},

		// HELD: Kernel#load / require / require_relative LFI (CWE-98). The sink
		// is precise (@global bare call, clean on literal paths), but the tsflow
		// source matcher binds an internal `.each do |path|` block variable named
		// `path` to the ruby.rails.request.path source by name, producing a false
		// positive on idiomatic migration/plugin loaders (e.g. Discourse's
		// DatabaseRestorer `all_migration_files.each { |path| require path }`).
		// That is a source-side over-match the sink can't compensate for, and it
		// is the dominant real-world shape of dynamic require/load, so this stays
		// held until the source heuristic tightens. A missing detection beats it.

		// --- SSRF / remote path traversal: Net::FTP (CWE-918 / CWE-22) ---
		// Net::FTP.open(host) / .new(host) / #connect(host) open a connection
		// to a user-supplied host (SSRF / internal-service probe). The file
		// transfer methods (#getbinaryfile/#gettextfile/#get/#put/#putbinaryfile)
		// take a tainted remote/local path (path traversal). Net::FTP has no
		// receiver-name collision with the existing Net::HTTP sinks (ftp≠http),
		// so these are genuinely new coverage. Shares the SnkURLFetch
		// SSRF-allowlist sanitizers with the other HTTP-client sinks.
		{
			ID:            "ruby.net_ftp.open",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `Net::FTP\.(?:open|new)\s*\(`,
			ObjectType:    "Net::FTP",
			MethodName:    "open/new",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Net::FTP.open/new with a tainted host argument — connects to an attacker-controlled FTP server (SSRF / internal-network probe). Validate the host against an allowlist",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.net_ftp.connect",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangRuby,
			Pattern:       `\.connect\s*\(`,
			ObjectType:    "Net::FTP",
			MethodName:    "connect",
			DangerousArgs: []int{0},
			Severity:      rules.High,
			Description:   "Net::FTP#connect with a tainted host argument — opens an FTP control connection to an attacker-controlled host (SSRF / internal-network probe). Validate the host against an allowlist",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},
		{
			ID:            "ruby.net_ftp.getfile",
			Category:      taint.SnkFileRead,
			Language:      rules.LangRuby,
			Pattern:       `\.(?:getbinaryfile|gettextfile|get)\s*\(`,
			ObjectType:    "Net::FTP",
			MethodName:    "getbinaryfile/gettextfile/get",
			DangerousArgs: []int{0},
			Severity:      rules.Medium,
			Description:   "Net::FTP#getbinaryfile/gettextfile/get with a tainted remote path — downloads an attacker-chosen remote file (remote path traversal); the local-destination arg can also escape its intended directory. Constrain both paths",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},
	}
}
