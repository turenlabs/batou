# Lua Language Support

## Overview

GTSS provides security scanning for Lua code, covering the standard library (`os`, `io`, `debug`, `load*`), OpenResty/ngx_lua (`ngx.req`, `ngx.var`, `ngx.say`, `ngx.redirect`), Redis Lua scripting (`KEYS`, `ARGV`, `redis.call`), LOVE2D (`love.filesystem`), database libraries (lua-resty-mysql, ngx_postgres), and serialization libraries (serpent, cjson). Lua is scanned through regex-based rules and taint source-to-sink tracking.

## Detection

Lua files are identified by the `.lua` file extension. Detection is handled in `internal/analyzer/analyzer.go`:

| Extension | Language Constant |
|-----------|-------------------|
| `.lua`    | `rules.LangLua`  |

Files matching `.lua` are scanned through two analysis layers:
- **Layer 1**: Regex-based rules (pattern matching on source code)
- **Layer 2**: Taint analysis (source-to-sink tracking with sanitizer recognition)

Test files (paths matching `_test.lua`) are excluded from scanning to reduce false positives.

## Taint Analysis Coverage

The Lua taint catalog is defined in `internal/taint/languages/lua_*.go` and tracks 16 sources, 18 sinks, and 10 sanitizers.

### Sources (User Input Entry Points)

#### OpenResty / ngx_lua Input

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `lua.ngx.req.get_uri_args` | `ngx.req.get_uri_args()` | URI query arguments |
| `lua.ngx.req.get_post_args` | `ngx.req.get_post_args()` | POST body arguments |
| `lua.ngx.req.get_body_data` | `ngx.req.get_body_data()` | Raw request body |
| `lua.ngx.req.get_headers` | `ngx.req.get_headers()` | Request headers |
| `lua.ngx.var` | `ngx.var.*` | Nginx variables (may contain user input) |
| `lua.ngx.req.raw_header` | `ngx.req.raw_header()` | Raw request header string |

#### Standard Library Input

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `lua.io.read` | `io.read()` | Standard input read |
| `lua.io.lines` | `io.lines()` | Standard input line iterator |
| `lua.os.getenv` | `os.getenv()` | Environment variable |
| `lua.arg` | `arg[]` | Command-line argument table |

#### LOVE2D Input

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `lua.love.filesystem.read` | `love.filesystem.read()` | LOVE2D file read |
| `lua.love.filesystem.lines` | `love.filesystem.lines()` | LOVE2D file lines iterator |

#### Redis Lua Scripting

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `lua.redis.keys` | `KEYS[]` | Redis KEYS table (external input) |
| `lua.redis.argv` | `ARGV[]` | Redis ARGV table (external input) |

#### Network Input

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `lua.socket.receive` | `:receive()` | LuaSocket network receive |
| `lua.ngx.socket.tcp.receive` | `tcp:receive()` / `sock:receive()` | OpenResty cosocket TCP receive |

### Sinks (Dangerous Functions)

#### Command Injection (CWE-78)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `lua.os.execute` | `os.execute()` | Critical | OS command execution |
| `lua.io.popen` | `io.popen()` | Critical | Process pipe execution |

#### Code Injection (CWE-94)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `lua.loadstring` | `loadstring()` | Critical | Dynamic code loading from string |
| `lua.load` | `load()` | Critical | Dynamic code loading |
| `lua.dofile` | `dofile()` | Critical | Execute Lua file at path |
| `lua.loadfile` | `loadfile()` | Critical | Load Lua file at path |

#### SQL Injection (CWE-89)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `lua.resty.mysql.query` | `db:query()` | Critical | MySQL query via lua-resty-mysql |
| `lua.ngx.postgres.query` | `ngx.location.capture` | Critical | PostgreSQL query via ngx_postgres |

#### Path Traversal / File Operations (CWE-22)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `lua.io.open` | `io.open()` | High | File open with tainted path |
| `lua.os.remove` | `os.remove()` | High | File removal with tainted path |
| `lua.os.rename` | `os.rename()` | High | File rename with tainted paths |

#### XSS / HTML Output (CWE-79)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `lua.ngx.say` | `ngx.say()` | High | OpenResty response output |
| `lua.ngx.print` | `ngx.print()` | High | OpenResty response output |

#### Open Redirect (CWE-601)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `lua.ngx.redirect` | `ngx.redirect()` | High | OpenResty HTTP redirect |
| `lua.ngx.exec` | `ngx.exec()` | High | OpenResty internal redirect |

#### Other Sinks

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `lua.redis.call` | `redis.call()` | High | Redis command execution |
| `lua.loadstring.deser` | `loadstring()` (network context) | Critical | Deserialization via code loading |
| `lua.ngx.log` | `ngx.log()` | Medium | Log injection |

### Sanitizers

| Sanitizer ID | Pattern | Neutralizes | Description |
|-------------|---------|-------------|-------------|
| `lua.ngx.escape_uri` | `ngx.escape_uri()` | HTML output, redirect | OpenResty URI escaping |
| `lua.ngx.encode_args` | `ngx.encode_args()` | HTML output, redirect | OpenResty argument encoding |
| `lua.ngx.encode_base64` | `ngx.encode_base64()` | HTML output | Base64 encoding |
| `lua.ndk.set_var.set_quote_sql_str` | `ndk.set_var.set_quote_sql_str()` | SQL | SQL string quoting |
| `lua.resty.mysql.quote` | `:quote_sql_str()` | SQL | MySQL string quoting |
| `lua.tonumber` | `tonumber()` | SQL, command, file | Numeric conversion |
| `lua.string.match.validate` | `string.match()` | SQL, command, HTML | Pattern validation |
| `lua.string.find.validate` | `string.find()` | SQL, command | Pattern search validation |
| `lua.string.gsub.dotdot` | `string.gsub()` (path) | File write | Directory traversal stripping |
| `lua.resty.template.escape` | `template.escape()` | HTML output, template | HTML escaping |

## Rule Coverage

The following Lua-specific regex rules are registered in `internal/rules/lua/lua.go`:

### LUA-001: Command Injection

| Rule ID | Name | Severity | Patterns |
|---------|------|----------|----------|
| GTSS-LUA-001 | Command Injection | Critical | `os.execute()` with variable/concat; `io.popen()` with variable/concat |

### LUA-002: Code Injection

| Rule ID | Name | Severity | Patterns |
|---------|------|----------|----------|
| GTSS-LUA-002 | Code Injection | Critical | `loadstring()` with non-literal; `load()` with variable; `dofile()` with variable; `loadfile()` with variable |

### LUA-003: SQL Injection

| Rule ID | Name | Severity | Patterns |
|---------|------|----------|----------|
| GTSS-LUA-003 | SQL Injection | Critical | SQL keywords with `..` concat; `string.format()` with SQL keywords |

### LUA-004: Path Traversal

| Rule ID | Name | Severity | Patterns |
|---------|------|----------|----------|
| GTSS-LUA-004 | Path Traversal | High | `io.open()` with variable/concat path (without sanitization) |

### LUA-005: XSS via OpenResty Response

| Rule ID | Name | Severity | Patterns |
|---------|------|----------|----------|
| GTSS-LUA-005 | XSS via OpenResty Response | High | `ngx.say()`/`ngx.print()` with variable/concat in files with user input sources and no escaping |

### LUA-006: Insecure Deserialization

| Rule ID | Name | Severity | Patterns |
|---------|------|----------|----------|
| GTSS-LUA-006 | Insecure Deserialization | High | `loadstring()` with network data context; `serpent.load()` |

### LUA-007: Open Redirect

| Rule ID | Name | Severity | Patterns |
|---------|------|----------|----------|
| GTSS-LUA-007 | Open Redirect | Medium | `ngx.redirect()` with variable/concat URL in files with user input |

### LUA-008: Debug Library in Production

| Rule ID | Name | Severity | Patterns |
|---------|------|----------|----------|
| GTSS-LUA-008 | Debug Library in Production | Medium | `debug.getinfo()`, `debug.sethook()`, `debug.setmetatable()`, `debug.setlocal()`, `debug.setupvalue()`, `debug.getlocal()`, `debug.getupvalue()` |

## Example Detections

### Command Injection via os.execute

```lua
-- DETECTED: GTSS-LUA-001 (Critical) + taint flow lua.ngx.req.get_uri_args -> lua.os.execute
local args = ngx.req.get_uri_args()
local host = args["host"]
os.execute("ping -c 3 " .. host)
```

GTSS flags the `os.execute()` call with string concatenation using the `..` operator and traces user input from `ngx.req.get_uri_args()` (source) through `host` into `os.execute()` (sink).

### SQL Injection via String Concatenation

```lua
-- DETECTED: GTSS-LUA-003 (Critical) + taint flow lua.ngx.req.get_uri_args -> lua.resty.mysql.query
local args = ngx.req.get_uri_args()
local name = args["name"]
local sql = "SELECT * FROM users WHERE name = '" .. name .. "'"
db:query(sql)
```

GTSS detects SQL keywords concatenated with a variable using `..` and traces the taint from user input to the database query.

### Code Injection via loadstring

```lua
-- DETECTED: GTSS-LUA-002 (Critical)
ngx.req.read_body()
local code = ngx.req.get_body_data()
local fn = loadstring(code)
if fn then fn() end
```

GTSS detects `loadstring()` with a non-literal argument, which allows arbitrary code execution if the input is user-controlled.

### XSS via ngx.say

```lua
-- DETECTED: GTSS-LUA-005 (High) + taint flow lua.ngx.req.get_uri_args -> lua.ngx.say
local args = ngx.req.get_uri_args()
local name = args["name"]
ngx.say("<h1>Hello, " .. name .. "</h1>")
```

GTSS detects `ngx.say()` outputting concatenated user input without HTML escaping in a file that has user input sources.

## Safe Patterns

### Parameterized SQL with quote_sql_str

```lua
-- SAFE: SQL string properly quoted
local args = ngx.req.get_uri_args()
local name = args["name"]
local quoted = ngx.quote_sql_str(name)
local sql = "SELECT * FROM users WHERE name = " .. quoted
db:query(sql)
```

GTSS recognizes `ngx.quote_sql_str()`, `ndk.set_var.set_quote_sql_str()`, and `:quote_sql_str()` as SQL sanitizers.

### Escaped Output with ngx.escape_uri

```lua
-- SAFE: HTML output with URI escaping
local args = ngx.req.get_uri_args()
local name = args["name"]
local escaped = ngx.escape_uri(name)
ngx.say("<h1>Hello, " .. escaped .. "</h1>")
```

GTSS recognizes `ngx.escape_uri()` as a sanitizer for HTML output sinks.

### Safe Deserialization with cjson

```lua
-- SAFE: JSON parsing instead of loadstring
local cjson = require("cjson")
ngx.req.read_body()
local body = ngx.req.get_body_data()
local data = cjson.decode(body)
```

Using `cjson.decode()` instead of `loadstring()` for deserialization is safe because JSON parsing cannot execute arbitrary code.

### Path Traversal Prevention

```lua
-- SAFE: Path sanitization before io.open
local filename = ngx.var.arg_file
filename = string.gsub(filename, "%.%.", "")
filename = string.gsub(filename, "/", "")
local f = io.open("/data/public/" .. filename, "r")
```

GTSS recognizes `string.gsub()` with `..` pattern removal as a path traversal sanitizer.

## Limitations

The following are known gaps or areas with reduced accuracy in Lua coverage:

- **Metatables and metamethods**: Taint tracking does not follow data through metatables (`__index`, `__newindex`, `__call`). Tainted data accessed through a metatable proxy may not be tracked.

- **Coroutine boundaries**: Taint tracking does not follow data across `coroutine.resume()`/`coroutine.yield()` boundaries.

- **Dynamic module loading**: `require()` with variable module names is not tracked as a code injection vector because Lua's `require()` uses `package.path` restrictions. However, if `package.path` is user-controlled, this becomes dangerous.

- **C extension modules**: Security properties of C extension modules loaded via `require()` are not analyzed. Vulnerabilities in C libraries called from Lua are outside the scanner's scope.

- **LuaJIT FFI**: LuaJIT's FFI library (`ffi.cdef`, `ffi.new`, `ffi.cast`) enables direct C interop that bypasses Lua's safety guarantees. These patterns are not currently tracked.

- **Multi-file taint**: Taint does not propagate across Lua `require()` boundaries. A tainted value passed to a function in another module may lose its taint status.

- **Template engines**: While `lua-resty-template` auto-escaping is recognized, other template engines (lustache, etlua) may not be tracked as sanitizers.

- **Redis Lua sandboxing**: Redis restricts available Lua functions, but the scanner does not differentiate between Redis-embedded Lua and standalone Lua. Some findings (e.g., `os.execute` in Redis scripts) may be false positives since Redis blocks these functions.

- **OpenResty phases**: OpenResty executes Lua code in different nginx phases (rewrite, access, content, log). The scanner does not consider phase restrictions when evaluating sink reachability.
