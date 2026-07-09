package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (perlCatalog) Sources() []taint.SourceDef {
	return []taint.SourceDef{
		// CGI.pm sources
		{ID: "perl.cgi.param", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$cgi->param\s*\(`, ObjectType: "CGI", MethodName: "param", Description: "CGI.pm request parameter", Assigns: "return"},
		{ID: "perl.cgi.q.param", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$q->param\s*\(`, ObjectType: "CGI", MethodName: "param", Description: "CGI.pm request parameter (via $q)", Assigns: "return"},
		{ID: "perl.cgi.vars", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$cgi->Vars`, ObjectType: "CGI", MethodName: "Vars", Description: "CGI.pm all parameters hash", Assigns: "return"},

		// PSGI/Plack sources
		{ID: "perl.psgi.query_string", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$env->\{'QUERY_STRING'\}|\$env->\{"QUERY_STRING"\}`, ObjectType: "PSGI", MethodName: "QUERY_STRING", Description: "PSGI query string", Assigns: "return"},
		{ID: "perl.plack.req.param", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->param\s*\(`, ObjectType: "Plack::Request", MethodName: "param", Description: "Plack request parameter", Assigns: "return"},
		{ID: "perl.plack.req.body_parameters", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->body_parameters`, ObjectType: "Plack::Request", MethodName: "body_parameters", Description: "Plack body parameters", Assigns: "return"},
		{ID: "perl.psgi.input", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$env->\{'psgi\.input'\}|\$env->\{"psgi\.input"\}`, ObjectType: "PSGI", MethodName: "psgi.input", Description: "PSGI input stream", Assigns: "return"},

		// Additional Plack::Request input sources — fills gaps in the foundational PSGI request API.
		// Plack::Request is the wrapper around $env that virtually every modern Perl web app uses
		// (Plack, Mojo's PSGI mode via Plack::Handler, Catalyst::Engine::PSGI, Dancer2's PSGI layer).
		// Reference: https://metacpan.org/pod/Plack::Request
		{ID: "perl.plack.req.parameters", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->parameters\b`, ObjectType: "Plack::Request", MethodName: "parameters", Description: "Plack combined query+body parameters (Hash::MultiValue)", Assigns: "return"},
		{ID: "perl.plack.req.query_parameters", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->query_parameters\b`, ObjectType: "Plack::Request", MethodName: "query_parameters", Description: "Plack query string parameters (Hash::MultiValue)", Assigns: "return"},
		{ID: "perl.plack.req.body", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->body\b`, ObjectType: "Plack::Request", MethodName: "body", Description: "Plack raw request body handle (used for JSON/XML APIs)", Assigns: "return"},
		{ID: "perl.plack.req.raw_body", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->raw_body\b`, ObjectType: "Plack::Request", MethodName: "raw_body", Description: "Plack raw request body string", Assigns: "return"},
		{ID: "perl.plack.req.content", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->content\b`, ObjectType: "Plack::Request", MethodName: "content", Description: "Plack request body content (alias for raw_body)", Assigns: "return"},
		{ID: "perl.plack.req.uploads", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->uploads\b`, ObjectType: "Plack::Request", MethodName: "uploads", Description: "Plack uploaded files hash (Hash::MultiValue of Plack::Request::Upload)", Assigns: "return"},
		{ID: "perl.plack.req.upload", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->upload\s*\(`, ObjectType: "Plack::Request", MethodName: "upload", Description: "Plack uploaded file by field name", Assigns: "return"},
		{ID: "perl.plack.req.path", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->path\b`, ObjectType: "Plack::Request", MethodName: "path", Description: "Plack request URL path (path traversal source)", Assigns: "return"},
		{ID: "perl.plack.req.path_info", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->path_info\b`, ObjectType: "Plack::Request", MethodName: "path_info", Description: "Plack request PATH_INFO (path traversal source)", Assigns: "return"},
		{ID: "perl.plack.req.request_uri", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->request_uri\b`, ObjectType: "Plack::Request", MethodName: "request_uri", Description: "Plack request REQUEST_URI (raw, undecoded)", Assigns: "return"},
		{ID: "perl.plack.req.uri", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->uri\b`, ObjectType: "Plack::Request", MethodName: "uri", Description: "Plack request URI object", Assigns: "return"},
		{ID: "perl.plack.req.referer", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->referer\b`, ObjectType: "Plack::Request", MethodName: "referer", Description: "Plack Referer header (XSS source if reflected)", Assigns: "return"},
		{ID: "perl.plack.req.user_agent", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->user_agent\b`, ObjectType: "Plack::Request", MethodName: "user_agent", Description: "Plack User-Agent header (XSS/log injection source)", Assigns: "return"},
		{ID: "perl.plack.req.cookie", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->cookies->\{`, ObjectType: "Plack::Request", MethodName: "cookies->", Description: "Plack request single cookie value", Assigns: "return"},
		// Plack::Request::Upload — the per-file upload object returned by ->upload / iterating ->uploads.
		// filename and basename are attacker-controlled (browser sends them) and are common path-traversal sources.
		{ID: "perl.plack.upload.filename", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$upload->filename\b`, ObjectType: "Plack::Request::Upload", MethodName: "filename", Description: "Plack uploaded file's client-supplied filename (path traversal source)", Assigns: "return"},
		{ID: "perl.plack.upload.basename", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$upload->basename\b`, ObjectType: "Plack::Request::Upload", MethodName: "basename", Description: "Plack uploaded file's client-supplied basename (path traversal source)", Assigns: "return"},

		// Mojolicious sources
		{ID: "perl.mojo.param", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$c->param\s*\(|\$self->param\s*\(`, ObjectType: "Mojolicious::Controller", MethodName: "param", Description: "Mojolicious controller parameter", Assigns: "return"},
		{ID: "perl.mojo.req.body", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$c->req->body|\$self->req->body`, ObjectType: "Mojolicious::Controller", MethodName: "req->body", Description: "Mojolicious request body", Assigns: "return"},
		{ID: "perl.mojo.req.json", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$c->req->json|\$self->req->json`, ObjectType: "Mojolicious::Controller", MethodName: "req->json", Description: "Mojolicious request JSON body", Assigns: "return"},
		{ID: "perl.mojo.stash", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$c->stash\s*\(`, ObjectType: "Mojolicious::Controller", MethodName: "stash", Description: "Mojolicious stash (may contain route params)", Assigns: "return"},

		// Dancer2 sources
		{ID: "perl.dancer2.params", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\bparams->\{`, ObjectType: "Dancer2", MethodName: "params", Description: "Dancer2 request parameters", Assigns: "return"},
		{ID: "perl.dancer2.body_parameters", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\bbody_parameters\b`, ObjectType: "Dancer2", MethodName: "body_parameters", Description: "Dancer2 body parameters", Assigns: "return"},
		{ID: "perl.dancer2.query_parameters", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\bquery_parameters\b`, ObjectType: "Dancer2", MethodName: "query_parameters", Description: "Dancer2 query parameters", Assigns: "return"},
		{ID: "perl.dancer2.param", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\bparam\s*\(`, ObjectType: "Dancer2", MethodName: "param", Description: "Dancer2 single parameter", Assigns: "return"},

		// Catalyst sources
		{ID: "perl.catalyst.req.param", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$c->req->param\s*\(|\$c->request->param\s*\(`, ObjectType: "Catalyst", MethodName: "req->param", Description: "Catalyst request parameter", Assigns: "return"},
		{ID: "perl.catalyst.req.params", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$c->req->params|\$c->request->params`, ObjectType: "Catalyst", MethodName: "req->params", Description: "Catalyst request parameters hash", Assigns: "return"},

		// CLI/stdin
		{ID: "perl.argv", Category: taint.SrcCLIArg, Language: rules.LangPerl, Pattern: `\@ARGV|\$ARGV\[`, ObjectType: "", MethodName: "@ARGV", Description: "Command-line arguments", Assigns: "return"},
		{ID: "perl.stdin", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `<STDIN>|\bSTDIN\b`, ObjectType: "", MethodName: "STDIN", Description: "Standard input", Assigns: "return"},
		{ID: "perl.stdin.readline", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `readline\s*\(\s*STDIN\s*\)`, ObjectType: "", MethodName: "readline(STDIN)", Description: "Standard input via readline", Assigns: "return"},

		// Environment
		{ID: "perl.env", Category: taint.SrcEnvVar, Language: rules.LangPerl, Pattern: `\$ENV\{`, ObjectType: "", MethodName: "%ENV", Description: "Environment variable", Assigns: "return"},

		// DBI result sources
		{ID: "perl.dbi.fetchrow", Category: taint.SrcDatabase, Language: rules.LangPerl, Pattern: `->fetchrow_array|->fetchrow_hashref|->fetchrow_arrayref|->fetchall_arrayref`, ObjectType: "DBI", MethodName: "fetchrow", Description: "DBI database query result", Assigns: "return"},
		{ID: "perl.dbi.selectrow_array", Category: taint.SrcDatabase, Language: rules.LangPerl, Pattern: `->selectrow_array\s*\(`, ObjectType: "", MethodName: "selectrow_array", Description: "DBI direct query+fetch single row as array", Assigns: "return"},
		{ID: "perl.dbi.selectrow_hashref", Category: taint.SrcDatabase, Language: rules.LangPerl, Pattern: `->selectrow_hashref\s*\(`, ObjectType: "", MethodName: "selectrow_hashref", Description: "DBI direct query+fetch single row as hashref", Assigns: "return"},
		{ID: "perl.dbi.selectrow_arrayref", Category: taint.SrcDatabase, Language: rules.LangPerl, Pattern: `->selectrow_arrayref\s*\(`, ObjectType: "", MethodName: "selectrow_arrayref", Description: "DBI direct query+fetch single row as arrayref", Assigns: "return"},
		{ID: "perl.dbi.selectall_arrayref", Category: taint.SrcDatabase, Language: rules.LangPerl, Pattern: `->selectall_arrayref\s*\(`, ObjectType: "", MethodName: "selectall_arrayref", Description: "DBI direct query+fetch all rows as arrayref", Assigns: "return"},
		{ID: "perl.dbi.selectall_hashref", Category: taint.SrcDatabase, Language: rules.LangPerl, Pattern: `->selectall_hashref\s*\(`, ObjectType: "", MethodName: "selectall_hashref", Description: "DBI direct query+fetch all rows as hash of hashes", Assigns: "return"},
		{ID: "perl.dbi.selectcol_arrayref", Category: taint.SrcDatabase, Language: rules.LangPerl, Pattern: `->selectcol_arrayref\s*\(`, ObjectType: "", MethodName: "selectcol_arrayref", Description: "DBI direct query+fetch single column as arrayref", Assigns: "return"},
		{ID: "perl.dbi.fetchall_hashref", Category: taint.SrcDatabase, Language: rules.LangPerl, Pattern: `->fetchall_hashref\s*\(`, ObjectType: "", MethodName: "fetchall_hashref", Description: "DBI statement handle fetch all rows as hash of hashes", Assigns: "return"},

		// File read sources
		{ID: "perl.file.read", Category: taint.SrcFileRead, Language: rules.LangPerl, Pattern: `\bread\s*\(\s*\$?\w+\s*,`, ObjectType: "", MethodName: "read", Description: "File read", Assigns: "return"},
		{ID: "perl.file.slurp", Category: taint.SrcFileRead, Language: rules.LangPerl, Pattern: `File::Slurp::read_file|\bread_file\s*\(`, ObjectType: "File::Slurp", MethodName: "read_file", Description: "File::Slurp file read", Assigns: "return"},

		// JSON deserialization
		{ID: "perl.json.decode", Category: taint.SrcDeserialized, Language: rules.LangPerl, Pattern: `decode_json\s*\(|from_json\s*\(|JSON->new->decode\s*\(`, ObjectType: "JSON", MethodName: "decode_json", Description: "JSON decoded data", Assigns: "return"},

		// Mojolicious uploads
		{ID: "perl.mojo.upload", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$c->req->upload\s*\(|\$self->req->upload\s*\(`, ObjectType: "Mojolicious::Controller", MethodName: "req->upload", Description: "Mojolicious file upload", Assigns: "return"},

		// HTTP headers
		{ID: "perl.mojo.headers", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$c->req->headers->header\s*\(|\$self->req->headers->header\s*\(`, ObjectType: "Mojolicious::Controller", MethodName: "req->headers->header", Description: "Mojolicious request header", Assigns: "return"},
		{ID: "perl.cgi.http", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$cgi->http\s*\(|\$q->http\s*\(|\$ENV\{'HTTP_`, ObjectType: "CGI", MethodName: "http/HTTP_*", Description: "CGI HTTP header value", Assigns: "return"},
		{ID: "perl.plack.header", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->header\s*\(|\$env->\{'HTTP_`, ObjectType: "Plack::Request", MethodName: "header", Description: "Plack request header", Assigns: "return"},
		{ID: "perl.catalyst.header", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$c->req->header\s*\(|\$c->request->header\s*\(`, ObjectType: "Catalyst", MethodName: "req->header", Description: "Catalyst request header", Assigns: "return"},

		// Plack cookies
		{ID: "perl.plack.cookies", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$req->cookies|cookie_jar`, ObjectType: "Plack::Request", MethodName: "cookies", Description: "Plack request cookies", Assigns: "return"},

		// Mojo cookies
		{ID: "perl.mojo.cookie", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$c->cookie\s*\(|\$self->cookie\s*\(`, ObjectType: "Mojolicious::Controller", MethodName: "cookie", Description: "Mojolicious cookie value", Assigns: "return"},

		// YAML deserialization
		{ID: "perl.yaml.load", Category: taint.SrcDeserialized, Language: rules.LangPerl, Pattern: `YAML::Load\s*\(|YAML::XS::Load\s*\(|LoadFile\s*\(`, ObjectType: "YAML", MethodName: "YAML::Load", Description: "YAML deserialized data", Assigns: "return"},

		// --- Additional Perl sources ---
		{
			ID:          "perl.lwp.response",
			Category:    taint.SrcNetwork,
			Language:    rules.LangPerl,
			Pattern:     `LWP::UserAgent.*->get\s*\(|HTTP::Response.*->content`,
			ObjectType:  "LWP::UserAgent",
			MethodName:  "get/content",
			Description: "LWP HTTP response content",
			Assigns:     "return",
		},
		{
			ID:          "perl.file.sysread",
			Category:    taint.SrcFileRead,
			Language:    rules.LangPerl,
			Pattern:     `read\s*\(\s*\w+\s*,|sysread\s*\(`,
			ObjectType:  "",
			MethodName:  "read/sysread",
			Description: "Perl file read into buffer",
			Assigns:     "return",
		},
		{
			ID:          "perl.dbi.fetchrow.v2",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `->fetchrow_array\s*\(|->fetchrow_hashref\s*\(|->fetchall_arrayref\s*\(`,
			ObjectType:  "DBI",
			MethodName:  "fetchrow_array/fetchrow_hashref",
			Description: "DBI database query result data",
			Assigns:     "return",
		},

		// --- CGI.pm missing sources ---
		{
			ID:          "perl.cgi.cookie",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$cgi->cookie\s*\(|\$q->cookie\s*\(`,
			ObjectType:  "CGI",
			MethodName:  "cookie",
			Description: "CGI.pm cookie value",
			Assigns:     "return",
		},
		{
			ID:          "perl.cgi.path_info",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$cgi->path_info\s*\(|\$q->path_info\s*\(`,
			ObjectType:  "CGI",
			MethodName:  "path_info",
			Description: "CGI.pm PATH_INFO (URL path component)",
			Assigns:     "return",
		},
		{
			ID:          "perl.cgi.url",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$cgi->url\s*\(|\$q->url\s*\(`,
			ObjectType:  "CGI",
			MethodName:  "url",
			Description: "CGI.pm request URL",
			Assigns:     "return",
		},
		{
			ID:          "perl.cgi.user_agent",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$cgi->user_agent\s*\(|\$q->user_agent\s*\(`,
			ObjectType:  "CGI",
			MethodName:  "user_agent",
			Description: "CGI.pm User-Agent header",
			Assigns:     "return",
		},
		{
			ID:          "perl.cgi.referer",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$cgi->referer\s*\(|\$q->referer\s*\(`,
			ObjectType:  "CGI",
			MethodName:  "referer",
			Description: "CGI.pm HTTP Referer header",
			Assigns:     "return",
		},
		{
			ID:          "perl.cgi.remote_host",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$cgi->remote_host\s*\(|\$q->remote_host\s*\(`,
			ObjectType:  "CGI",
			MethodName:  "remote_host",
			Description: "CGI.pm client hostname (spoofable via X-Forwarded-For)",
			Assigns:     "return",
		},

		// --- Dancer2 missing sources ---
		{
			ID:          "perl.dancer2.cookie",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `=\s*cookie\s*['"]|\(\s*cookie\s*['"]`,
			ObjectType:  "Dancer2",
			MethodName:  "cookie",
			Description: "Dancer2 cookie value",
			Assigns:     "return",
		},
		{
			ID:          "perl.dancer2.upload",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `=\s*upload\s*['"]|\(\s*upload\s*['"]`,
			ObjectType:  "Dancer2",
			MethodName:  "upload",
			Description: "Dancer2 file upload",
			Assigns:     "return",
		},
		{
			ID:          "perl.dancer2.request.path",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `request->path\b`,
			ObjectType:  "Dancer2",
			MethodName:  "request->path",
			Description: "Dancer2 request path",
			Assigns:     "return",
		},
		{
			ID:          "perl.dancer2.request.uri",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `request->uri\b`,
			ObjectType:  "Dancer2",
			MethodName:  "request->uri",
			Description: "Dancer2 request URI",
			Assigns:     "return",
		},
		{
			ID:          "perl.dancer2.request.header",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `request->header\s*\(`,
			ObjectType:  "Dancer2",
			MethodName:  "request->header",
			Description: "Dancer2 request header",
			Assigns:     "return",
		},

		// --- Catalyst missing sources ---
		{
			ID:          "perl.catalyst.req.cookie",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$c->req->cookie\s*\(|\$c->request->cookie\s*\(`,
			ObjectType:  "Catalyst",
			MethodName:  "req->cookie",
			Description: "Catalyst request cookie",
			Assigns:     "return",
		},
		{
			ID:          "perl.catalyst.req.cookies",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$c->req->cookies\b|\$c->request->cookies\b`,
			ObjectType:  "Catalyst",
			MethodName:  "req->cookies",
			Description: "Catalyst request cookies hash",
			Assigns:     "return",
		},
		{
			ID:          "perl.catalyst.req.upload",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$c->req->upload\s*\(|\$c->request->upload\s*\(`,
			ObjectType:  "Catalyst",
			MethodName:  "req->upload",
			Description: "Catalyst file upload",
			Assigns:     "return",
		},
		{
			ID:          "perl.catalyst.req.body",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$c->req->body\b|\$c->request->body\b`,
			ObjectType:  "Catalyst",
			MethodName:  "req->body",
			Description: "Catalyst raw request body",
			Assigns:     "return",
		},
		{
			ID:          "perl.catalyst.req.body_data",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$c->req->body_data\b|\$c->request->body_data\b`,
			ObjectType:  "Catalyst",
			MethodName:  "req->body_data",
			Description: "Catalyst parsed request body (JSON/form)",
			Assigns:     "return",
		},
		{
			ID:          "perl.catalyst.req.uri",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$c->req->uri\b|\$c->request->uri\b`,
			ObjectType:  "Catalyst",
			MethodName:  "req->uri",
			Description: "Catalyst request URI",
			Assigns:     "return",
		},
		{
			ID:          "perl.catalyst.req.path",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$c->req->path\b|\$c->request->path\b`,
			ObjectType:  "Catalyst",
			MethodName:  "req->path",
			Description: "Catalyst request path",
			Assigns:     "return",
		},

		// --- HTTP client response sources (external data) ---
		{
			ID:          "perl.mojo.ua.response",
			Category:    taint.SrcNetwork,
			Language:    rules.LangPerl,
			Pattern:     `Mojo::UserAgent->new.*->get\s*\(|->result->body\b|->result->json\b`,
			ObjectType:  "Mojo::UserAgent",
			MethodName:  "get/result->body",
			Description: "Mojo::UserAgent HTTP response content",
			Assigns:     "return",
		},
		{
			ID:          "perl.http.tiny.response",
			Category:    taint.SrcNetwork,
			Language:    rules.LangPerl,
			Pattern:     `HTTP::Tiny->new->get\s*\(|HTTP::Tiny->new->post\s*\(`,
			ObjectType:  "HTTP::Tiny",
			MethodName:  "get/post",
			Description: "HTTP::Tiny HTTP response",
			Assigns:     "return",
		},

		// ── External data sources (SrcExternal) ─────────────────────
		// Message queues, caches, and cloud services that receive
		// attacker-controlled data from external systems.

		// Redis (Redis.pm / Redis::Fast — widely deployed in Perl infrastructure)
		{
			ID:          "perl.redis.get",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->get\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "get",
			Description: "Redis key-value retrieval",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.mget",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->mget\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "mget",
			Description: "Redis multi-key retrieval",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.hgetall",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->hgetall\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "hgetall",
			Description: "Redis hash retrieval (all fields)",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.blpop",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->blpop\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "blpop",
			Description: "Redis blocking list pop (message from queue pattern)",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.subscribe",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->subscribe\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "subscribe",
			Description: "Redis pub/sub message subscription",
			Assigns:     "return",
		},

		// Additional Redis.pm read commands — second-order taint via cached
		// attacker-controlled values. Same threat model as perl.redis.get /
		// perl.redis.hgetall: a value previously written by an untrusted user
		// is later retrieved and flowed into a sink (SQL, command, eval, etc.).
		// Mirrors lua.resty.redis.* (PR #505), go.redis.* (PR #647), and the
		// in-flight redis-rb / phpredis / ioredis / Jedis / StackExchange.Redis
		// PRs across other languages.
		{
			ID:          "perl.redis.hget",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->hget\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "hget",
			Description: "Redis single hash field retrieval",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.hkeys",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->hkeys\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "hkeys",
			Description: "Redis hash field-name retrieval",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.hvals",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->hvals\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "hvals",
			Description: "Redis hash value retrieval",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.hmget",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->hmget\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "hmget",
			Description: "Redis multi-field hash retrieval",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.lrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->lrange\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "lrange",
			Description: "Redis list range retrieval",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.lpop",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->lpop\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "lpop",
			Description: "Redis list left-pop",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.rpop",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->rpop\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "rpop",
			Description: "Redis list right-pop",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.lindex",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->lindex\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "lindex",
			Description: "Redis list element by index",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.smembers",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->smembers\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "smembers",
			Description: "Redis set member retrieval",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.srandmember",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->srandmember\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "srandmember",
			Description: "Redis random set member retrieval",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.spop",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->spop\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "spop",
			Description: "Redis set pop",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.zrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->zrange\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "zrange",
			Description: "Redis sorted-set range retrieval",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.zrevrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->zrevrange\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "zrevrange",
			Description: "Redis sorted-set reverse-range retrieval",
			Assigns:     "return",
		},
		{
			ID:          "perl.redis.zrangebyscore",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$redis->zrangebyscore\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "zrangebyscore",
			Description: "Redis sorted-set retrieval by score range",
			Assigns:     "return",
		},

		// Memcached (Cache::Memcached::Fast — production-grade C-based client)
		// ObjectType "Memcached" matches $memd via abbreviation prefix heuristic
		{
			ID:          "perl.memcached.get",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$memd->get\s*\(`,
			ObjectType:  "Memcached",
			MethodName:  "get",
			Description: "Memcached cache retrieval",
			Assigns:     "return",
		},
		{
			ID:          "perl.memcached.get_multi",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$memd->get_multi\s*\(`,
			ObjectType:  "",
			MethodName:  "get_multi",
			Description: "Memcached multi-key cache retrieval",
			Assigns:     "return",
		},

		// RabbitMQ (Net::AMQP::RabbitMQ — production AMQP client)
		// Empty ObjectType: recv/basic_get are AMQP-specific method names
		{
			ID:          "perl.rabbitmq.recv",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$mq->recv\s*\(`,
			ObjectType:  "",
			MethodName:  "recv",
			Description: "RabbitMQ consumer message receive",
			Assigns:     "return",
		},
		{
			ID:          "perl.rabbitmq.basic_get",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$mq->basic_get\s*\(`,
			ObjectType:  "",
			MethodName:  "basic_get",
			Description: "RabbitMQ synchronous message get",
			Assigns:     "return",
		},

		// Kafka (Net::Kafka — librdkafka bindings, Booking.com maintained)
		// ObjectType "Consumer" matches $consumer variable name
		{
			ID:          "perl.kafka.poll",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$consumer->poll\s*\(`,
			ObjectType:  "Consumer",
			MethodName:  "poll",
			Description: "Kafka consumer message poll",
			Assigns:     "return",
		},

		// Stomp (Net::Stomp — ActiveMQ/RabbitMQ STOMP protocol)
		{
			ID:          "perl.stomp.receive_frame",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$stomp->receive_frame\s*\(`,
			ObjectType:  "Net::Stomp",
			MethodName:  "receive_frame",
			Description: "STOMP message frame receive",
			Assigns:     "return",
		},

		// ZeroMQ (ZMQ::LibZMQ3 — low-level ZMQ bindings)
		// @global: these are bare function calls, not method calls
		{
			ID:          "perl.zmq.recv",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\bzmq_recv\s*\(`,
			ObjectType:  "@global",
			MethodName:  "zmq_recv",
			Description: "ZeroMQ socket receive",
			Assigns:     "return",
		},
		{
			ID:          "perl.zmq.recvmsg",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\bzmq_recvmsg\s*\(`,
			ObjectType:  "@global",
			MethodName:  "zmq_recvmsg",
			Description: "ZeroMQ message object receive",
			Assigns:     "return",
		},

		// AWS SQS (Paws::SQS — official AWS SDK for Perl)
		{
			ID:          "perl.paws.sqs.receive",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$sqs->ReceiveMessage\s*\(`,
			ObjectType:  "Paws::SQS",
			MethodName:  "ReceiveMessage",
			Description: "AWS SQS message receive",
			Assigns:     "return",
		},

		// AWS S3 (Paws::S3)
		{
			ID:          "perl.paws.s3.getobject",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$s3->GetObject\s*\(`,
			ObjectType:  "Paws::S3",
			MethodName:  "GetObject",
			Description: "AWS S3 object retrieval (potentially untrusted content)",
			Assigns:     "return",
		},

		// AWS Kinesis (Paws::Kinesis) — stream-consumer read.
		// A producer may write attacker-controlled bytes to a Kinesis shard on
		// one request; a consumer reads them back later via GetRecords. The
		// record Data is therefore second-order tainted when it reaches a sink.
		{
			ID:          "perl.paws.kinesis.getrecords",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$kinesis->GetRecords\s*\(`,
			ObjectType:  "Paws::Kinesis",
			MethodName:  "GetRecords",
			Description: "AWS Kinesis stream records read (second-order; record data may be attacker-controlled)",
			Assigns:     "return",
		},

		// AWS Lambda (Paws::Lambda) — invocation response payload.
		// The Payload returned by Invoke is the output of the invoked function,
		// which may itself process untrusted input, so the response is treated
		// as a second-order external source.
		{
			ID:          "perl.paws.lambda.invoke",
			Category:    taint.SrcExternal,
			Language:    rules.LangPerl,
			Pattern:     `\$lambda->Invoke\s*\(`,
			ObjectType:  "Paws::Lambda",
			MethodName:  "Invoke",
			Description: "AWS Lambda invocation response payload (second-order; may be attacker-controlled)",
			Assigns:     "return",
		},

		// ── Deserialization result sources (SrcDeserialized) ──────────
		// When data passes through a deserializer, the output values may
		// contain attacker-controlled content stored earlier. Tracking
		// these as sources enables second-order injection detection
		// (e.g., Storable::thaw → system()).

		// Storable (core module, binary Perl serialization)
		{
			ID:          "perl.storable.thaw.source",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangPerl,
			Pattern:     `Storable::thaw\s*\(|(?:^|[^\w>])thaw\s*\(`,
			ObjectType:  "",
			MethodName:  "thaw",
			Description: "Storable::thaw output — deserialized Perl data structure may contain attacker-stored values",
			Assigns:     "return",
		},
		{
			ID:          "perl.storable.retrieve.source",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangPerl,
			Pattern:     `Storable::retrieve\s*\(|(?:^|[^\w>])retrieve\s*\(`,
			ObjectType:  "",
			MethodName:  "retrieve",
			Description: "Storable::retrieve output — reads and deserializes from file, data may be tainted",
			Assigns:     "return",
		},

		// Sereal (Booking.com binary format, ~500 CPAN dependents)
		{
			ID:          "perl.sereal.decode.method.source",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangPerl,
			Pattern:     `Sereal::Decoder.*->decode\s*\(`,
			ObjectType:  "Sereal::Decoder",
			MethodName:  "decode",
			Description: "Sereal decoded data via method call — binary deserialization output may contain attacker-stored values",
			Assigns:     "return",
		},
		{
			ID:          "perl.sereal.decode.func.source",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangPerl,
			Pattern:     `decode_sereal\s*\(`,
			ObjectType:  "",
			MethodName:  "decode_sereal",
			Description: "Sereal decoded data via functional interface — binary deserialization output may contain attacker-stored values",
			Assigns:     "return",
		},

		// Data::MessagePack (binary serialization, used in RPC/caching)
		{
			ID:          "perl.msgpack.unpack.func.source",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangPerl,
			Pattern:     `unpack_msgpack\s*\(`,
			ObjectType:  "",
			MethodName:  "unpack_msgpack",
			Description: "MessagePack unpacked data via functional interface — may contain attacker-stored values",
			Assigns:     "return",
		},

		// XML::Simple (most-installed XML parser on CPAN, returns hashref)
		{
			ID:          "perl.xml.simple.xmlin.source",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangPerl,
			Pattern:     `XMLin\s*\(`,
			ObjectType:  "",
			MethodName:  "XMLin",
			Description: "XML::Simple XMLin output — parsed XML fields may contain attacker-stored values",
			Assigns:     "return",
		},

		// CBOR::XS (RFC 7049 binary format, used in IoT/WebAuthn)
		{
			ID:          "perl.cbor.decode.method.source",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangPerl,
			Pattern:     `CBOR::XS.*->decode\s*\(`,
			ObjectType:  "CBOR::XS",
			MethodName:  "decode",
			Description: "CBOR decoded data via method call — may contain attacker-stored values",
			Assigns:     "return",
		},
		{
			ID:          "perl.cbor.decode.func.source",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangPerl,
			Pattern:     `decode_cbor\s*\(`,
			ObjectType:  "",
			MethodName:  "decode_cbor",
			Description: "CBOR decoded data via functional interface — may contain attacker-stored values",
			Assigns:     "return",
		},

		// Archive entry sources (CWE-22 Zip Slip / Tar Slip) — entry paths
		// inside attacker-supplied archives are attacker-controlled and must
		// not be used as a destination path without sanitization.
		{
			ID:          "perl.archive.tar.full_path",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$\w+->full_path\b`,
			ObjectType:  "",
			MethodName:  "full_path",
			Description: "Archive::Tar::File entry path inside an archive — attacker-controlled in malicious tarballs (Tar Slip / CWE-22)",
			Assigns:     "return",
		},
		{
			ID:          "perl.archive.zip.fileName",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$\w+->fileName\b`,
			ObjectType:  "",
			MethodName:  "fileName",
			Description: "Archive::Zip::Member entry name inside an archive — attacker-controlled in malicious zip files (Zip Slip / CWE-22)",
			Assigns:     "return",
		},

		// Mojo::Pg::Results / Mojo::mysql::Results / Mojo::SQLite::Results
		// — second-order DB-read sources. A value previously written by an
		// untrusted user (CRUD endpoint, profile field, settings update) is
		// later fetched via the Mojolicious DB result iterator and flowed
		// into a sink (SQL, command, eval, etc.). Same threat model as the
		// existing perl.dbi.fetchrow.* / perl.redis.* second-order sources.
		// Mirrors groovy JdbcTemplate / MyBatis (PR #768), ruby Mysql2/PG
		// (PR #760), php pg_fetch (PR #753), python SQLAlchemy (PR #736)
		// in-flight DB-read source waves.
		//
		// ObjectType "Mojo::Pg::Results" lastPart "results" matches receivers
		// {results, result, res, re, r} via the matcher's HasPrefix heuristic,
		// covering Mojo::mysql::Results and Mojo::SQLite::Results identically
		// because they share the same trailing class name.
		{
			ID:          "perl.mojo.results.hash",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$\w+->hash\s*\(`,
			ObjectType:  "Mojo::Pg::Results",
			MethodName:  "hash",
			Description: "Mojo::Pg::Results / Mojo::mysql::Results / Mojo::SQLite::Results — next row as hashref (second-order taint from DB)",
			Assigns:     "return",
		},
		{
			ID:          "perl.mojo.results.hashes",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$\w+->hashes\s*\(`,
			ObjectType:  "Mojo::Pg::Results",
			MethodName:  "hashes",
			Description: "Mojo::Pg::Results / Mojo::mysql::Results / Mojo::SQLite::Results — all remaining rows as Mojo::Collection of hashrefs (second-order taint from DB)",
			Assigns:     "return",
		},
		{
			ID:          "perl.mojo.results.array",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$\w+->array\s*\(`,
			ObjectType:  "Mojo::Pg::Results",
			MethodName:  "array",
			Description: "Mojo::Pg::Results / Mojo::mysql::Results / Mojo::SQLite::Results — next row as arrayref (second-order taint from DB)",
			Assigns:     "return",
		},
		{
			ID:          "perl.mojo.results.arrays",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$\w+->arrays\s*\(`,
			ObjectType:  "Mojo::Pg::Results",
			MethodName:  "arrays",
			Description: "Mojo::Pg::Results / Mojo::mysql::Results / Mojo::SQLite::Results — all remaining rows as Mojo::Collection of arrayrefs (second-order taint from DB)",
			Assigns:     "return",
		},

		// MongoDB::Cursor — second-order NoSQL document read sources. The
		// Collection->find / aggregate sinks (perl.mongo.collection.find,
		// perl.mongo.collection.aggregate) flag user-controlled FILTERS; this
		// pair tracks the read path — documents previously stored by an
		// untrusted user are returned and may then flow into command, SQL,
		// eval, or HTML sinks (stored-XSS / second-order injection).
		//
		// ObjectType "MongoDB::Cursor" lastPart "cursor" matches receivers
		// {cursor, curso, curs, cur, cu, c} via the matcher's HasPrefix
		// heuristic.
		{
			ID:          "perl.mongo.cursor.next",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$\w+->next\s*\(`,
			ObjectType:  "MongoDB::Cursor",
			MethodName:  "next",
			Description: "MongoDB::Cursor next() — next document from a MongoDB query result (second-order NoSQL taint)",
			Assigns:     "return",
		},
		{
			ID:          "perl.mongo.cursor.all",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$\w+->all\s*\(`,
			ObjectType:  "MongoDB::Cursor",
			MethodName:  "all",
			Description: "MongoDB::Cursor all() — all remaining documents from a MongoDB query result (second-order NoSQL taint)",
			Assigns:     "return",
		},

		// --- Additional Mojolicious / Dancer / Catalyst request sources ---

		// Mojolicious
		{ID: "perl.mojo.controller.param", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$(?:c|self|app|tx)->param\s*\(`, ObjectType: "Mojolicious::Controller", MethodName: "param", Description: "Mojolicious $c->param($name) — combined query/body parameter", Assigns: "return"},
		{ID: "perl.mojo.controller.every_param", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$(?:c|self|app|tx)->every_param\s*\(`, ObjectType: "Mojolicious::Controller", MethodName: "every_param", Description: "Mojolicious $c->every_param — all values for a parameter name", Assigns: "return"},
		{ID: "perl.mojo.req.body", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `->req->body\b|->res->body\b`, ObjectType: "Mojo::Message::Request", MethodName: "body", Description: "Mojo::Message::Request->body — raw request body", Assigns: "return"},
		{ID: "perl.mojo.req.json", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `->req->json\b|->res->json\b`, ObjectType: "Mojo::Message::Request", MethodName: "json", Description: "Mojo::Message::Request->json — decoded JSON body", Assigns: "return"},
		{ID: "perl.mojo.req.headers", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `->req->headers\b|->res->headers\b`, ObjectType: "Mojo::Message::Request", MethodName: "headers", Description: "Mojo::Message::Request->headers — Mojo::Headers object", Assigns: "return"},
		{ID: "perl.mojo.req.url", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `->req->url\b|->res->url\b`, ObjectType: "Mojo::Message::Request", MethodName: "url", Description: "Mojo::Message::Request->url — request URL", Assigns: "return"},
		{ID: "perl.mojo.req.cookies", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `->req->cookies\b|->res->cookies\b`, ObjectType: "Mojo::Message::Request", MethodName: "cookies", Description: "Mojo::Message::Request->cookies — request cookies", Assigns: "return"},

		// Dancer / Dancer2
		{ID: "perl.dancer.params", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\bparams\s*(?:\(|->)`, ObjectType: "Dancer2::Core::Request", MethodName: "params", Description: "Dancer / Dancer2 params() — combined route/query/body parameters", Assigns: "return"},
		{ID: "perl.dancer.param", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\bparam\s*\(`, ObjectType: "Dancer2::Core::Request", MethodName: "param", Description: "Dancer / Dancer2 param('name') — single parameter accessor", Assigns: "return"},
		{ID: "perl.dancer.request_data", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\brequest\s*->\s*(?:body|content|headers|cookies|user_agent)\b`, ObjectType: "Dancer2::Core::Request", MethodName: "request.body/content/headers/cookies/user_agent", Description: "Dancer / Dancer2 request->body / content / headers / cookies / user_agent", Assigns: "return"},

		// Catalyst
		{ID: "perl.catalyst.request_params", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$c->req(?:uest)?->params\b|\$c->req(?:uest)?->parameters\b`, ObjectType: "Catalyst::Request", MethodName: "params/parameters", Description: "Catalyst $c->request->params / ->parameters — combined parameter accessor", Assigns: "return"},
		{ID: "perl.catalyst.request_body", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\$c->req(?:uest)?->body\b|\$c->req(?:uest)?->body_data\b`, ObjectType: "Catalyst::Request", MethodName: "body/body_data", Description: "Catalyst $c->request->body / ->body_data — raw / deserialised request body", Assigns: "return"},

		// --- Network sources — outbound HTTP / WS responses ---
		{ID: "perl.lwp.useragent_response_content", Category: taint.SrcNetwork, Language: rules.LangPerl, Pattern: `->decoded_content\s*\(|HTTP::Response.*->content\s*\(\s*\)`, ObjectType: "HTTP::Response", MethodName: "content/decoded_content", Description: "LWP::UserAgent HTTP::Response->content / ->decoded_content — body of an outbound HTTP response (server-attacker-controlled bytes)", Assigns: "return"},
		{ID: "perl.http_tiny.request", Category: taint.SrcNetwork, Language: rules.LangPerl, Pattern: `HTTP::Tiny->new[^;]*->(?:get|post|request)\s*\(`, ObjectType: "HTTP::Tiny", MethodName: "get/post/request", Description: "HTTP::Tiny ->get / ->post / ->request — returns hashref with 'content' field carrying outbound HTTP response body", Assigns: "return"},
		{ID: "perl.mojo_useragent_response", Category: taint.SrcNetwork, Language: rules.LangPerl, Pattern: `->res->body\b|->res->text\b|->res->json\b`, ObjectType: "Mojo::UserAgent", MethodName: "res.body/text/json", Description: "Mojo::UserAgent ->res->body / ->res->text / ->res->json — outbound HTTP response body", Assigns: "return"},
		{ID: "perl.io_socket_recv", Category: taint.SrcNetwork, Language: rules.LangPerl, Pattern: `IO::Socket::(?:INET|SSL)->new|->recv\s*\(`, ObjectType: "IO::Socket", MethodName: "recv", Description: "IO::Socket::INET / IO::Socket::SSL recv — remote peer bytes", Assigns: "return"},
		{ID: "perl.protocol_websocket", Category: taint.SrcNetwork, Language: rules.LangPerl, Pattern: `Protocol::WebSocket::Frame->new|AnyEvent::WebSocket`, ObjectType: "Protocol::WebSocket::Frame", MethodName: "frame", Description: "Protocol::WebSocket::Frame / AnyEvent::WebSocket — incoming WebSocket payload", Assigns: "return"},

		// --- JWT decoded claims (client-supplied token contents) ---
		// A JWT is sent by the client, so the decoded payload/claims are
		// attacker-controlled (even after signature verification the *values*
		// are user data, never authority over server-side logic). Tracking the
		// decode_jwt() / JSON::WebToken decode() return as user input enables
		// second-order flows: a claim such as `sub`/`name`/`role` reaching SQL,
		// command, file-path, eval, or HTML sinks. Pairs with the JWT crypto
		// sinks in perl_sinks.go.
		{ID: "perl.crypt.jwt.decode_jwt.source", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `\bdecode_jwt\s*\(`, ObjectType: "Crypt::JWT", MethodName: "decode_jwt", Description: "Crypt::JWT / JSON::WebToken decode_jwt() output — claims come from a client-supplied token (attacker-controlled values; second-order injection source)", Assigns: "return"},
		{ID: "perl.jsonwebtoken.decode.source", Category: taint.SrcUserInput, Language: rules.LangPerl, Pattern: `JSON::WebToken->decode\s*\(|JSON::WebToken::decode\s*\(`, ObjectType: "JSON::WebToken", MethodName: "decode", Description: "JSON::WebToken decode() output — claims come from a client-supplied token (attacker-controlled values; second-order injection source)", Assigns: "return"},

		// ── CGI::Application (CGI::App) request sources ───────────────
		// CGI::Application is one of the oldest, still widely-deployed Perl web
		// frameworks (the classic run-mode dispatcher that predates Catalyst;
		// ~hundreds of CPAN dependents, ::Plugin::* ecosystem, used by Krang CMS,
		// Bricolage, and many legacy enterprise apps). It is NOT covered by the
		// existing CGI.pm / Plack / Catalyst / Mojolicious / Dancer2 entries:
		// the framework's canonical user-input idiom is the *chained* accessor
		// `$self->query->param(...)` — the run-mode object ($self) exposes the
		// underlying CGI/CGI::Simple query object via ->query, then param/cookie/
		// upload/url_param read attacker data off it. Reference:
		// https://metacpan.org/pod/CGI::Application#query
		//
		// The structural receiver of the outer ->param call in `$self->query->param`
		// is `self` (perlVarName walks the inner invocant `$self->query` and returns
		// the first varname). Receiver "self" is too generic to scope on, so these
		// entries leave ObjectType empty and rely on the highly-specific
		// `->query->param`-style Pattern (no other Perl framework uses the
		// `<app>->query->{param,cookie,...}` chain) for precision. Receivers cover
		// the conventional run-mode object names: $self, $app, $webapp, $cgiapp, $c.
		{
			ID:          "perl.cgiapp.query.param",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$(?:self|app|webapp|cgiapp|c)->query->param\s*\(`,
			ObjectType:  "",
			MethodName:  "param",
			Description: "CGI::Application $self->query->param() — request parameter (query string or POST body)",
			Assigns:     "return",
		},
		{
			ID:          "perl.cgiapp.query.url_param",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$(?:self|app|webapp|cgiapp|c)->query->url_param\s*\(`,
			ObjectType:  "",
			MethodName:  "url_param",
			Description: "CGI::Application $self->query->url_param() — query-string-only request parameter",
			Assigns:     "return",
		},
		{
			ID:          "perl.cgiapp.query.cookie",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$(?:self|app|webapp|cgiapp|c)->query->cookie\s*\(`,
			ObjectType:  "",
			MethodName:  "cookie",
			Description: "CGI::Application $self->query->cookie() — request cookie value (attacker-controlled)",
			Assigns:     "return",
		},
		{
			ID:          "perl.cgiapp.query.upload",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$(?:self|app|webapp|cgiapp|c)->query->upload\s*\(`,
			ObjectType:  "",
			MethodName:  "upload",
			Description: "CGI::Application $self->query->upload() — uploaded file handle / client filename (path-traversal source)",
			Assigns:     "return",
		},
		{
			ID:          "perl.cgiapp.query.path_info",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$(?:self|app|webapp|cgiapp|c)->query->path_info\s*\(`,
			ObjectType:  "",
			MethodName:  "path_info",
			Description: "CGI::Application $self->query->path_info() — PATH_INFO URL component (path-traversal source)",
			Assigns:     "return",
		},
		{
			ID:          "perl.cgiapp.query.param_fetch",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPerl,
			Pattern:     `\$(?:self|app|webapp|cgiapp|c)->query->param_fetch\s*\(`,
			ObjectType:  "",
			MethodName:  "param_fetch",
			Description: "CGI::Application $self->query->param_fetch() — arrayref of values for a multi-valued request parameter",
			Assigns:     "return",
		},

		// AWS DynamoDB (Paws::DynamoDB — official AWS SDK for Perl).
		// DynamoDB read operations return items whose attribute values may
		// have been written by an untrusted user on an earlier request.
		// Tracking the results as second-order sources flags the classic
		// store-then-read injection chain (e.g., a value saved via PutItem
		// is later read with GetItem and concatenated into a command/SQL/
		// eval/HTML sink). Mirrors the cross-language DynamoDB second-order
		// read-source wave (Python boto3, Go aws-sdk-go-v2).
		// https://metacpan.org/pod/Paws::DynamoDB
		{
			ID:          "perl.paws.dynamodb.getitem",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$dynamodb->GetItem\s*\(`,
			ObjectType:  "Paws::DynamoDB",
			MethodName:  "GetItem",
			Description: "AWS DynamoDB GetItem result (second-order; attributes may be attacker-controlled)",
			Assigns:     "return",
		},
		{
			ID:          "perl.paws.dynamodb.batchgetitem",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$dynamodb->BatchGetItem\s*\(`,
			ObjectType:  "Paws::DynamoDB",
			MethodName:  "BatchGetItem",
			Description: "AWS DynamoDB BatchGetItem result (second-order; attributes may be attacker-controlled)",
			Assigns:     "return",
		},
		{
			ID:          "perl.paws.dynamodb.query",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$dynamodb->Query\s*\(`,
			ObjectType:  "Paws::DynamoDB",
			MethodName:  "Query",
			Description: "AWS DynamoDB Query result (second-order; attributes may be attacker-controlled)",
			Assigns:     "return",
		},
		{
			ID:          "perl.paws.dynamodb.scan",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$dynamodb->Scan\s*\(`,
			ObjectType:  "Paws::DynamoDB",
			MethodName:  "Scan",
			Description: "AWS DynamoDB Scan result (second-order; attributes may be attacker-controlled)",
			Assigns:     "return",
		},
		{
			ID:          "perl.paws.dynamodb.transactgetitems",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$dynamodb->TransactGetItems\s*\(`,
			ObjectType:  "Paws::DynamoDB",
			MethodName:  "TransactGetItems",
			Description: "AWS DynamoDB TransactGetItems result (second-order; attributes may be attacker-controlled)",
			Assigns:     "return",
		},

		// --- Search::Elasticsearch / OpenSearch::Client read-back sources ---
		// (second-order stored injection, SrcDatabase). The write side
		// (perl.elasticsearch.bulk/index/update_by_query/...) is already
		// modeled as SnkNoSQL/SnkEval sinks, but the documents that come BACK
		// out of the cluster were never treated as taint sources. A value an
		// untrusted user indexed on one request is returned verbatim inside
		// the `_source` of a later search/get/mget/scroll response; if that
		// document is then concatenated into a command/SQL/eval/HTML sink it
		// is a stored-injection (second-order) flow.
		//
		// Scoped via ObjectType "Search::Elasticsearch" so the matcher's
		// last-part abbreviation heuristic fires only for receiver names that
		// are a prefix of "elasticsearch" — i.e. the canonical documented
		// client handle `$e` (used verbatim in the perl.elasticsearch.* sink
		// descriptions above) as well as `$elastic` / `$elasticsearch`. This
		// keeps generic method names like `search` / `get` from colliding
		// with unrelated objects: Net::LDAP's `$ldap->search` ("ldap") and
		// Redis's `$r->mget` ("r"/"redis") are not prefixes of
		// "elasticsearch" and therefore do not match.
		//
		// NOTE: the very common abbreviation `$es` is NOT a prefix of
		// "elasticsearch" (second letter "l" vs "s"), so it is currently
		// missed by the abbreviation heuristic. Catching `$es` cleanly would
		// require a scoped receiver-alias special-case in matcher.go (like the
		// existing em→EntityManager / pb→ProcessBuilder mappings) — out of
		// scope for this pure catalog-add cycle.
		// Refs:
		//   https://metacpan.org/pod/Search::Elasticsearch
		//   https://metacpan.org/pod/Search::Elasticsearch::Client::8_0::Direct
		{
			ID:          "perl.elasticsearch.search",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$\w+->search\s*\(`,
			ObjectType:  "Search::Elasticsearch",
			MethodName:  "search",
			Description: "Search::Elasticsearch $e->search() result — hits returned from the cluster (second-order; document _source may be attacker-controlled)",
			Assigns:     "return",
		},
		{
			ID:          "perl.elasticsearch.get",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$\w+->get\s*\(`,
			ObjectType:  "Search::Elasticsearch",
			MethodName:  "get",
			Description: "Search::Elasticsearch $e->get() result — single document fetched by id (second-order; _source may be attacker-controlled)",
			Assigns:     "return",
		},
		{
			ID:          "perl.elasticsearch.mget",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$\w+->mget\s*\(`,
			ObjectType:  "Search::Elasticsearch",
			MethodName:  "mget",
			Description: "Search::Elasticsearch $e->mget() result — multi-get document batch (second-order; _source may be attacker-controlled)",
			Assigns:     "return",
		},
		{
			ID:          "perl.elasticsearch.scroll",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPerl,
			Pattern:     `\$\w+->scroll\s*\(`,
			ObjectType:  "Search::Elasticsearch",
			MethodName:  "scroll",
			Description: "Search::Elasticsearch $e->scroll() result — next batch of scroll hits (second-order; document _source may be attacker-controlled)",
			Assigns:     "return",
		},
	}
}
