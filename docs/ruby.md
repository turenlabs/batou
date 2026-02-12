# Ruby Language Support

## Overview

GTSS provides comprehensive security scanning for Ruby code, covering Rails, Sinatra, Grape, Hanami, and Rack applications. Analysis spans three layers: regex-based pattern matching (Layer 1), taint source-to-sink tracking (Layer 2), and interprocedural call graph analysis (Layer 3). Ruby coverage includes 30+ taint sources across 7 frameworks, 60+ sinks spanning 14 vulnerability categories, and 25+ sanitizer recognitions to reduce false positives.

## Detection

Ruby files are identified by file extension in the analyzer:

| Extension | Detected As |
|-----------|-------------|
| `.rb`     | Ruby        |
| `.erb`    | Ruby        |

Detection is handled in `internal/analyzer/analyzer.go` via the `extToLanguage` map. Both pure Ruby source files and ERB templates are scanned.

## Taint Analysis Coverage

Taint analysis tracks data flow from user-controlled sources through the program to dangerous sinks. Sanitizers along the path neutralize taint for specific sink categories.

### Sources (User Input Entry Points)

Sources are defined in `internal/taint/languages/ruby_sources.go`.

#### Rails (ActionController / ActionDispatch)

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `ruby.rails.params` | `params[...]` | Rails request parameters |
| `ruby.rails.params.fetch` | `params.fetch(...)` | Rails params.fetch |
| `ruby.rails.params.require` | `params.require(...)` | Rails strong parameters entry |
| `ruby.rails.request.headers` | `request.headers[...]` | HTTP request headers |
| `ruby.rails.request.cookies` | `request.cookies[...]` | Request cookies |
| `ruby.rails.request.body` | `request.body` | Raw request body |
| `ruby.rails.request.raw_post` | `request.raw_post` | Raw POST body |

#### Sinatra

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `ruby.sinatra.params` | `params[...]` | Sinatra request parameters |
| `ruby.sinatra.request.body.read` | `request.body.read` | Sinatra request body |
| `ruby.sinatra.request.env` | `request.env[...]` | Sinatra environment variables |

#### Grape

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `ruby.grape.params` | `params[...]` | Grape API parameters |
| `ruby.grape.declared_params` | `declared_params` | Grape declared parameters |

#### Hanami

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `ruby.hanami.params` | `params[...]` | Hanami action parameters |

#### Rack

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `ruby.rack.request.params` | `Rack::Request.new(...)` | Rack request object |
| `ruby.rack.env.query_string` | `env['QUERY_STRING']` | Rack query string |
| `ruby.rack.env.rack_input` | `env['rack.input']` | Rack input stream |

#### ActionCable

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `ruby.actioncable.params` | `params[...]` | ActionCable channel parameters |

#### CLI, Environment, and File

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `ruby.argv` | `ARGV` | Command-line arguments |
| `ruby.stdin.gets` | `STDIN.gets` | Standard input |
| `ruby.env` | `ENV[...]` | Environment variables |
| `ruby.file.read` | `File.read(...)` | File read |
| `ruby.io.read` | `IO.read(...)` | IO read |

#### Deserialization and External

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `ruby.json.parse` | `JSON.parse(...)` | Parsed JSON data |
| `ruby.aws.lambda.event` | Lambda handler event | AWS Lambda event data |
| `ruby.aws.sqs.receive` | `.receive_message(...)` | AWS SQS message |
| `ruby.aws.s3.getobject` | `.get_object(...)` | AWS S3 object data |
| `ruby.gcp.pubsub.pull` | `subscription.pull` | GCP Pub/Sub message |

### Sinks (Dangerous Functions)

Sinks are defined in `internal/taint/languages/ruby_sinks.go`.

#### SQL Injection (CWE-89)

| Sink ID | Pattern | Severity | Framework |
|---------|---------|----------|-----------|
| `ruby.activerecord.execute` | `.execute(...)` | Critical | ActiveRecord |
| `ruby.activerecord.exec_query` | `.exec_query(...)` | Critical | ActiveRecord |
| `ruby.activerecord.connection.execute` | `ActiveRecord::Base.connection.execute(...)` | Critical | ActiveRecord |
| `ruby.activerecord.where.interpolation` | `.where("...#{...}")` | Critical | ActiveRecord |
| `ruby.activerecord.order.interpolation` | `.order("...#{...}")` | Critical | ActiveRecord |
| `ruby.sequel.db.run` | `DB.run(...)` | Critical | Sequel |
| `ruby.sequel.db.fetch` | `DB.fetch(...)` | Critical | Sequel |
| `ruby.sequel.db.execute` | `DB.execute(...)` | Critical | Sequel |
| `ruby.sequel.where.interpolation` | `.where("...#{...}")` | Critical | Sequel |
| `ruby.arel.sql` | `Arel.sql(...)` | Critical | Arel |

#### Command Injection (CWE-78)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `ruby.system` | `system(...)` | Critical |
| `ruby.exec` | `exec(...)` | Critical |
| `ruby.backticks` | `` `...` `` | Critical |
| `ruby.percent_x` | `%x(...)` | Critical |
| `ruby.open3.capture2` | `Open3.capture2(...)` | Critical |
| `ruby.io.popen` | `IO.popen(...)` | Critical |
| `ruby.kernel.open` | `Kernel.open(...)` | Critical |
| `ruby.open.pipe` | `open("\|...")` | Critical |
| `ruby.docker.exec` | `container.exec(...)` | Critical |

#### Code Evaluation (CWE-94)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `ruby.eval` | `eval(...)` | Critical |
| `ruby.send` | `.send(...)` | High |
| `ruby.public_send` | `.public_send(...)` | High |
| `ruby.redis.eval` | `redis.eval(...)` | Critical |

#### XSS / HTML Output (CWE-79)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `ruby.rails.render.html` | `render html:` | High |
| `ruby.rails.render.inline` | `render inline:` | High |
| `ruby.erb.raw_output` | `<%== %>` | High |
| `ruby.rails.raw` | `raw(...)` | High |
| `ruby.rails.html_safe` | `.html_safe` | High |

#### File Operations / Path Traversal (CWE-22)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `ruby.file.open` | `File.open(...)` | High |
| `ruby.file.write` | `File.write(...)` | High |
| `ruby.fileutils` | `FileUtils.*` | High |
| `ruby.rails.render.file` | `render file:` | High |
| `ruby.tempfile.new` | `Tempfile.new(...)` | Medium |
| `ruby.activestorage.filename` | `.attach(... filename:)` | High |

#### Deserialization (CWE-502)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `ruby.marshal.load` | `Marshal.load(...)` | Critical |
| `ruby.yaml.load` | `YAML.load(...)` | Critical |
| `ruby.nokogiri.xml.parse` | `Nokogiri::XML(...)` | High |
| `ruby.nokogiri.html.parse` | `Nokogiri::HTML(...)` | High |

#### SSRF / URL Fetch (CWE-918)

| Sink ID | Pattern | Severity |
|---------|---------|----------|
| `ruby.net.http.get` | `Net::HTTP.get(...)` | High |
| `ruby.httparty.get` | `HTTParty.get(...)` | High |
| `ruby.faraday.get` | `Faraday.get(...)` | High |
| `ruby.open_uri.open` | `open("https://...")` | High |
| `ruby.uri.open` | `URI.open(...)` | High |
| `ruby.resolv.getaddress` | `Resolv.getaddress(...)` | High |

#### Other Sinks

| Sink ID | Category | Severity |
|---------|----------|----------|
| `ruby.rails.redirect_to` | Open Redirect (CWE-601) | High |
| `ruby.erb.new` | Template Injection (CWE-1336) | High |
| `ruby.actionmailer.header_injection` | Header Injection (CWE-93) | High |
| `ruby.net.smtp.sendmail` | SMTP Injection (CWE-93) | High |
| `ruby.redis.call` | Command Injection (CWE-77) | High |
| `ruby.bunny.publish` | AMQP Injection (CWE-77) | Medium |
| `ruby.crypto.digest.md5` | Weak Hash (CWE-328) | Medium |
| `ruby.crypto.digest.sha1` | Weak Hash (CWE-328) | Medium |
| `ruby.crypto.openssl.weak_cipher` | Weak Cipher (CWE-327) | High |
| `ruby.crypto.openssl.ecb_mode` | Weak Cipher (CWE-327) | High |
| `ruby.crypto.insecure_rand` | Insecure Random (CWE-338) | High |
| `ruby.logger.*` / `ruby.rails.logger.*` | Log Injection (CWE-117) | Medium |

### Sanitizers (Safe Patterns)

Sanitizers are defined in `internal/taint/languages/ruby_sanitizers.go`. When a sanitizer is detected in the data flow path, taint is neutralized for the corresponding sink categories.

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `ruby.erb.html_escape` | `ERB::Util.html_escape(...)` | HTML Output |
| `ruby.rails.h` | `h(...)` | HTML Output |
| `ruby.rails.sanitize` | `sanitize(...)` | HTML Output |
| `ruby.rack.utils.escape_html` | `Rack::Utils.escape_html(...)` | HTML Output |
| `ruby.loofah.scrub` | `Loofah.fragment(...).scrub` | HTML Output |
| `ruby.shellwords.escape` | `Shellwords.escape(...)` | Command |
| `ruby.shellwords.shellescape` | `Shellwords.shellescape(...)` | Command |
| `ruby.to_i` | `.to_i` | SQL, Command |
| `ruby.to_f` | `.to_f` | SQL, Command |
| `ruby.file.basename` | `File.basename(...)` | File Write |
| `ruby.activerecord.sanitize_sql` | `ActiveRecord::Base.sanitize_sql(...)` | SQL |
| `ruby.activerecord.where.parameterized` | `.where(key: value)` | SQL |
| `ruby.sequel.where.parameterized` | `.where(key: value)` | SQL |
| `ruby.sequel.placeholder` | `.where("...?", val)` | SQL |
| `ruby.cgi.escape` | `CGI.escape(...)` | Redirect, HTML Output |
| `ruby.yaml.safe_load` | `YAML.safe_load(...)` | Deserialize |
| `ruby.nokogiri.nonet` | `Nokogiri::XML(..., NONET)` | Deserialize, URL Fetch |
| `ruby.activestorage.sanitize_filename` | `ActiveStorage::Filename.new(...).sanitized` | File Write |
| `ruby.uri.encode_www_form_component` | `URI.encode_www_form_component(...)` | Redirect, URL Fetch |
| `ruby.ipaddr.validate` | `IPAddr.new(...).include?(...)` | URL Fetch |
| `ruby.uri.parse.host` | `URI.parse(...).host` | URL Fetch, Redirect |
| `ruby.crypto.bcrypt.create` | `BCrypt::Password.create(...)` | Crypto |
| `ruby.crypto.bcrypt.compare` | `BCrypt::Password.new(...)==` | Crypto |
| `ruby.crypto.securerandom` | `SecureRandom.*` | Crypto |
| `ruby.crypto.openssl.hmac` | `OpenSSL::HMAC.*` | Crypto |
| `ruby.crypto.secure_compare` | `ActiveSupport::SecurityUtils.secure_compare(...)` | Crypto |

## Rule Coverage

The following Layer 1 regex rules apply to Ruby files. Rules with `LangAny` also apply but are not Ruby-specific.

### Injection

| Rule ID | Name | Description |
|---------|------|-------------|
| GTSS-INJ-001 | SQL Injection | String interpolation in `.where()`, `.execute()`, raw SQL concatenation |
| GTSS-INJ-002 | Command Injection | `system()`, backticks, `%x()` with interpolated variables |
| GTSS-INJ-003 | Code Injection | `eval()`, `send()`, `public_send()` with dynamic input |
| GTSS-INJ-004 | LDAP Injection | LDAP filter string concatenation |
| GTSS-INJ-005 | Template Injection (SSTI) | `ERB.new()` with user-controlled templates |
| GTSS-INJ-006 | XPath Injection | XPath query string concatenation |
| GTSS-INJ-007 | NoSQL Injection | MongoDB `$where` with string concatenation, unsafe `$regex` |
| GTSS-INJ-008 | GraphQL Injection | GraphQL query string concatenation |

### XSS

| Rule ID | Name | Description |
|---------|------|-------------|
| GTSS-XSS-004 | Unescaped Template Output | `raw()`, `.html_safe` bypassing auto-escaping |
| GTSS-XSS-008 | Server-Side Rendering XSS | `render html:` with unescaped user input |
| GTSS-XSS-011 | Reflected XSS | `params` directly rendered in response |

### Path Traversal

| Rule ID | Name | Description |
|---------|------|-------------|
| GTSS-TRV-001 | Path Traversal | File operations with user-controlled paths (`send_file`, `File.read`, `File.join`) |
| GTSS-TRV-002 | File Inclusion | Dynamic `require`, `load` with variable input |

### Cryptography

| Rule ID | Name | Description |
|---------|------|-------------|
| GTSS-CRY-010 | Weak PRNG | `rand()` / `srand()` in security-sensitive contexts |
| GTSS-CRY-011 | Predictable Seed | `srand()` with fixed or time-based seeds |

### Secrets

| Rule ID | Name | Description |
|---------|------|-------------|
| GTSS-SEC-001 | Hardcoded Password | Password/secret string literals in assignments |
| GTSS-SEC-005 | JWT Secret | Hardcoded JWT signing keys |

### Authentication

| Rule ID | Name | Description |
|---------|------|-------------|
| GTSS-AUTH-001 | Hardcoded Credentials | Authentication checks against hardcoded values |
| GTSS-AUTH-003 | CORS Wildcard | Overly permissive CORS configuration |
| GTSS-AUTH-004 | Session Fixation | Login without `reset_session` |
| GTSS-AUTH-005 | Weak Password Policy | Password length requirements below 8 characters |

### Generic

| Rule ID | Name | Description |
|---------|------|-------------|
| GTSS-GEN-001 | Debug Mode Enabled | Production debug configuration |
| GTSS-GEN-002 | Unsafe Deserialization | `Marshal.load`, `YAML.load` on untrusted data |
| GTSS-GEN-004 | Open Redirect | `redirect_to` with user-controlled URL |
| GTSS-GEN-006 | Race Condition (TOCTOU) | Check-then-use patterns without synchronization |
| GTSS-GEN-007 | Mass Assignment | `update_attributes(params)` without strong parameters |
| GTSS-GEN-008 | Code-as-String Eval | Dangerous calls inside `eval()` string arguments |
| GTSS-GEN-009 | XML Parser Misconfig | XXE-enabling XML parser configuration |

### Logging

| Rule ID | Name | Description |
|---------|------|-------------|
| GTSS-LOG-001 | Unsanitized Log Input | `params` passed directly to logger calls |
| GTSS-LOG-002 | CRLF Log Injection | String interpolation of user input in log calls |
| GTSS-LOG-003 | Sensitive Data in Logs | Logging passwords, tokens, API keys |

### Validation

| Rule ID | Name | Description |
|---------|------|-------------|
| GTSS-VAL-001 | Direct Parameter Usage | `params` used without any validation nearby |
| GTSS-VAL-003 | Missing Length Validation | User input stored without size checks |
| GTSS-VAL-004 | Missing Allowlist Validation | User input used as dynamic property keys |

### SSRF

| Rule ID | Name | Description |
|---------|------|-------------|
| GTSS-SSRF-001 | URL From User Input | HTTP requests with user-derived URLs (applies to all languages) |
| GTSS-SSRF-002 | Internal Network Access | Requests to private IPs or cloud metadata (applies to all languages) |

## Example Detections

### SQL Injection via String Interpolation

```ruby
class UsersController < ApplicationController
  def search
    name = params[:name]
    @users = User.where("name LIKE '%#{name}%'")
    render json: @users
  end
end
```

**Triggers**: GTSS-INJ-001 (SQL Injection) -- string interpolation `#{name}` inside a `.where()` string argument allows an attacker to inject arbitrary SQL.

### Command Injection via system()

```ruby
class FileController < ApplicationController
  def download
    filename = params[:file]
    system("cp /uploads/#{filename} /tmp/download")
    send_file "/tmp/download"
  end
end
```

**Triggers**: GTSS-INJ-002 (Command Injection) -- user-controlled `filename` is interpolated into a shell command string passed to `system()`.

### Unsafe Deserialization via Marshal.load

```ruby
class SessionController < ApplicationController
  def restore
    cookie_data = cookies[:session_data]
    decoded = Base64.decode64(cookie_data)
    @session_obj = Marshal.load(decoded)
  end
end
```

**Triggers**: GTSS-GEN-002 (Unsafe Deserialization) and taint sink `ruby.marshal.load` (CWE-502) -- `Marshal.load` on user-controlled cookie data enables arbitrary code execution.

## Safe Patterns

### Parameterized SQL Queries

```ruby
class UsersController < ApplicationController
  def search
    name = params[:name]
    @users = User.where("name LIKE ?", "%#{name}%")
    render json: @users
  end

  def show
    @user = User.where(id: params[:id])
    render json: @user
  end
end
```

**Not flagged**: Placeholder `?` syntax and hash-style `.where(key: value)` are recognized as parameterized queries. The sanitizers `ruby.activerecord.where.parameterized` and `ruby.sequel.placeholder` neutralize SQL taint.

### Safe Command Execution with Array Arguments

```ruby
require 'open3'

class FileController < ApplicationController
  def convert
    input_path = params[:path]
    stdout, stderr, status = Open3.capture3("convert", input_path, "-resize", "100x100", "/tmp/thumb.png")
    if status.success?
      send_file "/tmp/thumb.png"
    end
  end
end
```

**Not flagged**: Using `Open3.capture3` with separate string arguments (array form) prevents shell interpretation. No shell metacharacter injection is possible.

### Properly Escaped HTML Output

```ruby
class CommentsController < ApplicationController
  def preview
    @preview = sanitize(params[:content])
  end

  def render_message
    message = ERB::Util.html_escape(params[:message])
    render html: message
  end
end
```

**Not flagged**: `sanitize()` and `ERB::Util.html_escape()` are recognized sanitizers that neutralize HTML output taint, preventing XSS.

## Limitations

- **ERB template analysis is line-based**: GTSS scans `.erb` files as Ruby but does not parse the ERB template structure. Complex multi-line ERB expressions or embedded HTML logic may not be fully analyzed.
- **No Gemfile dependency awareness**: GTSS does not read `Gemfile` or `Gemfile.lock` to determine which frameworks are in use. It applies all Ruby framework patterns regardless of actual dependencies.
- **Metaprogramming blind spots**: Ruby's `define_method`, `method_missing`, `class_eval`, and similar metaprogramming constructs are not tracked. Dynamically defined methods that introduce vulnerabilities will be missed.
- **No SSRF-specific regex rules**: While SSRF is covered via taint sinks (`Net::HTTP.get`, `HTTParty.get`, `Faraday.get`, etc.) and the language-agnostic GTSS-SSRF-001/002 rules, there are no Ruby-specific SSRF regex rules. The DNS rebinding (GTSS-SSRF-003) and redirect following (GTSS-SSRF-004) rules do not currently cover Ruby.
- **No memory safety rules**: The `memory` rule category does not apply to Ruby (as expected for a memory-managed language).
- **Block/Proc taint propagation**: Taint is not tracked through Ruby blocks, procs, or lambdas. A tainted value passed into a `map`, `each`, or custom block may lose its taint tracking.
- **Rails view helpers**: Custom view helpers that wrap escaping logic are not recognized as sanitizers unless they match a known pattern.
- **Confidence decay**: When tainted data passes through unknown Ruby methods, taint confidence decays by 0.8x per hop. After several unknown method calls, taint may drop below the reporting threshold.
