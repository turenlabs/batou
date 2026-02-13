package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
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
	}
}
