package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
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

		// File read sources
		{ID: "perl.file.read", Category: taint.SrcFileRead, Language: rules.LangPerl, Pattern: `read\s*\(\s*\$?\w+\s*,`, ObjectType: "", MethodName: "read", Description: "File read", Assigns: "return"},
		{ID: "perl.file.slurp", Category: taint.SrcFileRead, Language: rules.LangPerl, Pattern: `File::Slurp::read_file|read_file\s*\(`, ObjectType: "File::Slurp", MethodName: "read_file", Description: "File::Slurp file read", Assigns: "return"},

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
	}
}
