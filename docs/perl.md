# Perl Language Support

## Overview

GTSS provides comprehensive security scanning for Perl code, covering CGI.pm, PSGI/Plack, Mojolicious, Dancer2, Catalyst, and DBI-based applications. Analysis spans all four layers: regex-based pattern matching (348 rules, Layer 1), tree-sitter AST structural analysis (Layer 2), taint source-to-sink tracking via the tree-sitter AST walker (Layer 3), and interprocedural call graph analysis (Layer 4). Perl coverage includes 25 taint sources across 6 frameworks, 27 sinks spanning 12 vulnerability categories, and 16 sanitizer recognitions to reduce false positives.

Perl taint analysis uses the tree-sitter AST walker (`internal/taint/tsflow/`), the same engine used by the other 14 supported languages. The tree-sitter-perl grammar (vendored from `github.com/tree-sitter-perl/tree-sitter-perl`, MIT license) provides structural AST parsing, enabling taint tracking through variable reassignment, complex expressions, and method call chains with higher precision than regex-based analysis.

## Detection

Perl files are identified by file extension in the analyzer:

| Extension | Detected As |
|-----------|-------------|
| `.pl`     | Perl        |
| `.pm`     | Perl        |
| `.cgi`    | Perl        |

Detection is handled in `internal/analyzer/analyzer.go` via the `extToLanguage` map.

## Taint Analysis Coverage

Taint analysis tracks data flow from user-controlled sources through the program to dangerous sinks. Sanitizers along the path neutralize taint for specific sink categories.

### Sources (User Input Entry Points)

Sources are defined in `internal/taint/languages/perl_sources.go`.

#### CGI.pm

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `perl.cgi.param` | `$cgi->param(...)` | CGI.pm request parameter |
| `perl.cgi.q.param` | `$q->param(...)` | CGI.pm parameter (via $q) |
| `perl.cgi.vars` | `$cgi->Vars` | CGI.pm all parameters hash |

#### PSGI/Plack

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `perl.psgi.query_string` | `$env->{'QUERY_STRING'}` | PSGI query string |
| `perl.plack.req.param` | `$req->param(...)` | Plack request parameter |
| `perl.plack.req.body_parameters` | `$req->body_parameters` | Plack body parameters |
| `perl.psgi.input` | `$env->{'psgi.input'}` | PSGI input stream |

#### Mojolicious

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `perl.mojo.param` | `$c->param(...)` | Mojolicious controller parameter |
| `perl.mojo.req.body` | `$c->req->body` | Mojolicious request body |
| `perl.mojo.req.json` | `$c->req->json` | Mojolicious request JSON body |
| `perl.mojo.stash` | `$c->stash(...)` | Mojolicious stash (route params) |

#### Dancer2

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `perl.dancer2.params` | `params->{...}` | Dancer2 request parameters |
| `perl.dancer2.body_parameters` | `body_parameters` | Dancer2 body parameters |
| `perl.dancer2.query_parameters` | `query_parameters` | Dancer2 query parameters |
| `perl.dancer2.param` | `param(...)` | Dancer2 single parameter |

#### Catalyst

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `perl.catalyst.req.param` | `$c->req->param(...)` | Catalyst request parameter |
| `perl.catalyst.req.params` | `$c->req->params` | Catalyst request parameters hash |

#### CLI, Environment, and File

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `perl.argv` | `@ARGV` | Command-line arguments |
| `perl.stdin` | `<STDIN>` | Standard input |
| `perl.env` | `$ENV{...}` | Environment variable |
| `perl.dbi.fetchrow` | `->fetchrow_*` | DBI database query result |
| `perl.file.read` | `read(...)` | File read |
| `perl.file.slurp` | `File::Slurp::read_file(...)` | File::Slurp file read |
| `perl.json.decode` | `decode_json(...)` | JSON decoded data |

### Sinks (Dangerous Functions)

Sinks are defined in `internal/taint/languages/perl_sinks.go`.

#### Command Injection (CWE-78)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `perl.system` | `system(...)` | Critical |
| `perl.exec` | `exec(...)` | Critical |
| `perl.backticks` | `` `...` `` | Critical |
| `perl.qx` | `qx(...)` | Critical |
| `perl.open.pipe` | `open(FH, "\|...")` | Critical |
| `perl.ipc.open2` | `IPC::Open2/Open3` | Critical |

#### SQL Injection (CWE-89)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `perl.dbi.do` | `$dbh->do(...)` | Critical |
| `perl.dbi.prepare` | `$dbh->prepare(...)` | High |
| `perl.dbi.selectrow` | `$dbh->selectrow_*(...)` | Critical |
| `perl.dbi.selectall` | `$dbh->selectall_*(...)` | Critical |

#### Code Injection (CWE-94)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `perl.eval` | `eval(...)` / `eval $var` | Critical |

#### File Operations / Path Traversal (CWE-22)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `perl.open` | `open(...)` | High |
| `perl.file.slurp.write` | `write_file(...)` | High |
| `perl.unlink` | `unlink(...)` | High |
| `perl.rename` | `rename(...)` | High |

#### Deserialization (CWE-502)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `perl.storable.thaw` | `Storable::thaw(...)` | Critical |
| `perl.storable.retrieve` | `Storable::retrieve(...)` | Critical |
| `perl.yaml.load` | `YAML::Load(...)` | Critical |

#### SSRF / URL Fetch (CWE-918)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `perl.lwp.get` | `LWP::UserAgent->get(...)` | High |
| `perl.http.tiny.get` | `HTTP::Tiny->get(...)` | High |

#### Other Sinks

| Sink ID | Category | Severity |
|---------|----------|----------|
| `perl.print.cgi` | XSS (CWE-79) | High |
| `perl.cgi.redirect` | Open Redirect (CWE-601) | High |
| `perl.net.ldap.search` | LDAP Injection (CWE-90) | High |
| `perl.log.warn` | Log Injection (CWE-117) | Medium |
| `perl.digest.md5` | Weak Hash (CWE-328) | Medium |
| `perl.digest.sha1` | Weak Hash (CWE-328) | Medium |
| `perl.rand` | Insecure Random (CWE-338) | Medium |

### Sanitizers (Safe Patterns)

Sanitizers are defined in `internal/taint/languages/perl_sanitizers.go`. When a sanitizer is detected in the data flow path, taint is neutralized for the corresponding sink categories.

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `perl.dbi.placeholder` | `$dbh->do("...?...", undef, ...)` | SQL |
| `perl.dbi.quote` | `$dbh->quote(...)` | SQL |
| `perl.html.entities.encode` | `encode_entities(...)` | HTML Output |
| `perl.cgi.escapehtml` | `CGI::escapeHTML(...)` | HTML Output |
| `perl.html.escape` | `HTML::Escape::escape_html(...)` | HTML Output |
| `perl.uri.escape` | `URI::Escape::uri_escape(...)` | Redirect, HTML Output |
| `perl.quotemeta` | `quotemeta(...)` / `\Q...\E` | Command, SQL |
| `perl.taint.check` | `Scalar::Util::tainted(...)` | Command, SQL, File |
| `perl.untaint.regex` | `=~ /^[.../` | Command, SQL, File |
| `perl.int.coerce` | `int(...)` | SQL, Command |
| `perl.file.basename` | `File::Basename::basename(...)` | File Write |
| `perl.file.spec.canonpath` | `File::Spec->canonpath(...)` | File Write |
| `perl.system.list` | `system('cmd', @args)` | Command |
| `perl.yaml.safeload` | `YAML::Safe` / `YAML::XS::SafeLoad` | Deserialize |
| `perl.crypt.urandom` | `Crypt::URandom` | Crypto |
| `perl.crypt.bcrypt` | `Crypt::Bcrypt` | Crypto |

## Rule Coverage

The following Layer 1 regex rules are Perl-specific (defined in `internal/rules/perl/perl.go`).

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-PL-001 | PerlCommandInjection | Critical | `system()`, `exec()`, backticks, `qx()`, `open(\|...)` with variable interpolation |
| GTSS-PL-002 | PerlSQLInjection | Critical | DBI `do()`, `prepare()`, `selectrow_*()`, `selectall_*()` with string interpolation or concatenation |
| GTSS-PL-003 | PerlCodeInjection | Critical | String `eval()` with variable or interpolated string argument |
| GTSS-PL-004 | PerlPathTraversal | High | Two-argument `open()` with variable, `open()` with user-controlled path |
| GTSS-PL-005 | PerlRegexDoS | Medium | User input in regex without `quotemeta()` or `\Q\E` escaping |
| GTSS-PL-006 | PerlCGIXSS | High | `print` with CGI parameters without HTML encoding |
| GTSS-PL-007 | PerlInsecureFileOps | High | Two-argument `open()`, `chmod 0777`, world-writable permissions |
| GTSS-PL-008 | PerlDeserialization | High/Critical | `Storable::thaw()`, `Storable::retrieve()`, `YAML::Load()` with untrusted input |
| GTSS-PL-009 | PerlLDAPInjection | High | `Net::LDAP` search with interpolated or concatenated filter |
| GTSS-PL-010 | PerlInsecureRandomness | Medium | `rand()` in security contexts, `srand(time)`, `srand()` with fixed seed |

### Cross-Language Rules That Apply to Perl

Rules with `LangAny` also apply to Perl files:

| Rule ID | Name | Description |
|---------|------|-------------|
| GTSS-SEC-001 | Hardcoded Password | Password/secret string literals in assignments |
| GTSS-SEC-005 | JWT Secret | Hardcoded JWT signing keys |
| GTSS-AUTH-001 | Hardcoded Credentials | Authentication checks against hardcoded values |
| GTSS-GEN-001 | Debug Mode Enabled | Production debug configuration |
| GTSS-GEN-002 | Unsafe Deserialization | Generic deserialization patterns |
| GTSS-LOG-001 | Unsanitized Log Input | User input in log statements |
| GTSS-SSRF-001 | URL From User Input | HTTP requests with user-derived URLs |
| GTSS-SSRF-002 | Internal Network Access | Requests to private IPs or cloud metadata |
| GTSS-AUTH-007 | Privilege Escalation | Privilege escalation patterns (CWE-269) |
| GTSS-GEN-012 | Insecure Download | Insecure download patterns (CWE-494) |
| GTSS-MISC-003 | Missing Security Headers | Missing security headers (CWE-1021, CWE-693) |
| GTSS-VAL-005 | File Upload Hardening | File upload hardening (CWE-434) |

## Example Detections

### SQL Injection via String Interpolation

```perl
use DBI;
my $name = $cgi->param('name');
$dbh->do("DELETE FROM users WHERE name = '$name'");
```

**Triggers**: GTSS-PL-002 (PerlSQLInjection) -- variable `$name` is interpolated into a double-quoted SQL string passed to `$dbh->do()`.

### Command Injection via system()

```perl
my $file = $cgi->param('file');
system("cat $file");
```

**Triggers**: GTSS-PL-001 (PerlCommandInjection) -- user-controlled `$file` is interpolated into a shell command string. An attacker can inject `; rm -rf /` or similar.

### Code Injection via eval()

```perl
my $expr = $cgi->param('expr');
my $result = eval($expr);
```

**Triggers**: GTSS-PL-003 (PerlCodeInjection) -- user-controlled `$expr` is passed directly to `eval()`, enabling arbitrary Perl code execution.

### Unsafe Deserialization via Storable::thaw()

```perl
use Storable qw(thaw);
my $data = $cgi->param('data');
my $obj = thaw($data);
```

**Triggers**: GTSS-PL-008 (PerlDeserialization) -- `Storable::thaw()` deserializes arbitrary Perl data structures, including objects with DESTROY methods that execute code.

### Two-Argument open() with User Input

```perl
my $file = $cgi->param('file');
open(my $fh, $file);
```

**Triggers**: GTSS-PL-004 (PerlPathTraversal) and GTSS-PL-007 (PerlInsecureFileOps) -- two-argument `open()` allows pipe injection if `$file` starts with `|` (e.g., `|rm -rf /`).

### LDAP Injection via Net::LDAP

```perl
use Net::LDAP;
my $user = $cgi->param('username');
my $result = $ldap->search(filter => "(uid=$user)");
```

**Triggers**: GTSS-PL-009 (PerlLDAPInjection) -- user input `$user` is interpolated into the LDAP filter string, allowing filter manipulation.

## Safe Patterns

### Parameterized SQL Queries

```perl
use DBI;
my $name = $cgi->param('name');
$dbh->do("DELETE FROM users WHERE name = ?", undef, $name);

my $sth = $dbh->prepare("SELECT * FROM users WHERE name = ?");
$sth->execute($name);
```

**Not flagged**: DBI placeholder `?` syntax with bound parameters is recognized as safe. The sanitizer `perl.dbi.placeholder` neutralizes SQL taint.

### List-Form system()

```perl
my $file = $cgi->param('file');
system('cat', $file);
```

**Not flagged**: List-form `system()` with separate arguments avoids shell interpretation. No shell metacharacter injection is possible.

### HTML-Encoded Output

```perl
use HTML::Entities;
my $name = $cgi->param('name');
print encode_entities($name);
```

**Not flagged**: `HTML::Entities::encode_entities()` is recognized as a sanitizer that neutralizes HTML output taint, preventing XSS.

### Eval Block for Exception Handling

```perl
eval {
    my $result = some_function();
};
if ($@) { warn "Error: $@"; }
```

**Not flagged**: `eval { }` block syntax is used for exception handling, not string evaluation. Only string `eval()` with variable arguments triggers the code injection rule.

### Quotemeta for Regex Safety

```perl
my $pattern = quotemeta($cgi->param('search'));
if ($text =~ /$pattern/) {
    print "found\n";
}
```

**Not flagged**: `quotemeta()` escapes all regex metacharacters, preventing ReDoS and regex injection.

## Limitations

- **No Perl taint mode awareness**: GTSS does not detect or respect Perl's built-in `-T` taint mode. Code running with taint mode may already have protections that GTSS is unaware of.
- **No CPAN module awareness**: GTSS does not read `cpanfile` or `Makefile.PL` to determine which modules are installed. It applies all framework patterns regardless of actual dependencies.
- **Metaprogramming blind spots**: Perl's `AUTOLOAD`, `can()`, symbol table manipulation, and `eval`-based method generation are not tracked. Dynamically defined subroutines that introduce vulnerabilities will be missed.
- **Block/closure taint propagation**: Taint is not tracked through Perl closures, anonymous subroutines, or higher-order function calls (`map`, `grep`, `sort` blocks).
- **No heredoc analysis**: Variables interpolated in heredoc strings (`<<EOF ... $var ... EOF`) are not currently tracked for injection patterns.
- **Two-argument open detection is conservative**: The regex pattern may miss some forms of two-argument `open()` with complex filehandle expressions.
- **Confidence decay**: When tainted data passes through unknown Perl functions, taint confidence decays by 0.8x per hop. After several unknown function calls, taint may drop below the reporting threshold.
- **No memory safety rules**: The `memory` rule category does not apply to Perl (as expected for a memory-managed language).
