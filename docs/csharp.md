# C# Language Support

## Overview

GTSS provides comprehensive security scanning for C# code, covering ASP.NET Core web applications, Entity Framework, Razor views, Blazor components, System.DirectoryServices (LDAP), and common .NET libraries. Analysis includes four layers: regex-based pattern rules (348 rules, including 10 C#-specific plus cross-language rules), tree-sitter AST structural analysis (comment-aware false positive filtering and structural code inspection via `internal/analyzer/`), intraprocedural taint tracking (source to sink with sanitizer recognition), and interprocedural call graph analysis.

C# taint analysis uses the tree-sitter AST walker (`internal/taint/tsflow/`) which provides accurate tracking through variable declarations, assignments, and invocation expressions by walking the parsed AST. The walker handles C#-specific patterns such as `equals_value_clause` initializers in variable declarations.

## Detection

C# files are identified by the `.cs` and `.csx` (C# script) file extensions. The `DetectLanguage` function in `internal/analyzer/analyzer.go` maps both extensions to the `LangCSharp` language constant.

## Taint Analysis Coverage

Taint analysis tracks data flow from untrusted sources through the program to dangerous sinks, recognizing sanitizer functions that neutralize specific threat categories.

### Sources (21 tracked)

Sources are entry points where untrusted data enters the application.

#### ASP.NET Core HTTP Request (6)

| ID | Method | Description |
|---|---|---|
| `csharp.httpcontext.request.query` | `HttpContext.Request.Query[]` | Query string parameter |
| `csharp.httpcontext.request.form` | `HttpContext.Request.Form[]` | Form field value |
| `csharp.httpcontext.request.headers` | `HttpContext.Request.Headers[]` | HTTP request header |
| `csharp.httpcontext.request.cookies` | `HttpContext.Request.Cookies[]` | HTTP cookie value |
| `csharp.httpcontext.request.body` | `HttpContext.Request.Body` | Request body stream |
| `csharp.httpcontext.request.path` | `HttpContext.Request.Path` | Request URL path |

#### ASP.NET Core Route Data (3)

| ID | Method | Description |
|---|---|---|
| `csharp.routedata.values` | `RouteData.Values[]` | Route data value |
| `csharp.httpcontext.request.routevalues` | `HttpContext.Request.RouteValues[]` | Route parameter |
| `csharp.httpcontext.getRouteValue` | `HttpContext.GetRouteValue()` | Named route value |

#### Model Binding Attributes (5)

| ID | Method | Description |
|---|---|---|
| `csharp.frombody` | `[FromBody]` | Request body deserialization |
| `csharp.fromquery` | `[FromQuery]` | Query string binding |
| `csharp.fromroute` | `[FromRoute]` | Route parameter binding |
| `csharp.fromform` | `[FromForm]` | Form data binding |
| `csharp.fromheader` | `[FromHeader]` | Header value binding |

#### File Upload (1)

| ID | Method | Description |
|---|---|---|
| `csharp.iformfile` | `IFormFile` | Uploaded file data |

#### IO / Environment (3)

| ID | Method | Description |
|---|---|---|
| `csharp.streamreader.readline` | `StreamReader.ReadLine()` | Stream input |
| `csharp.environment.getenvironmentvariable` | `Environment.GetEnvironmentVariable()` | Environment variable |
| `csharp.console.readline` | `Console.ReadLine()` | Console input |

#### Database Results (1)

| ID | Method | Description |
|---|---|---|
| `csharp.sqldatareader` | `SqlDataReader[]` | Database query result |

#### Deserialization / Network (2)

| ID | Method | Description |
|---|---|---|
| `csharp.jsonconvert.deserializeobject` | `JsonConvert.DeserializeObject()` | JSON deserialized data |
| `csharp.httpclient.getasync` | `HttpClient.GetAsync()` / `GetStringAsync()` | HTTP response data |

#### Cloud Service Sources (1)

| ID | Method | Description |
|---|---|---|
| `csharp.azure.functions.httprequest` | `HttpRequest req` (Azure Functions) | Azure Functions HTTP trigger |

### Sinks (60 tracked)

Sinks are dangerous operations where tainted data can cause vulnerabilities.

#### SQL Injection (CWE-89)

| ID | Method | Severity |
|---|---|---|
| `csharp.sqlcommand.new` | `new SqlCommand()` with string concat | Critical |
| `csharp.sqlcommand.commandtext` | `SqlCommand.CommandText` assignment | Critical |
| `csharp.ef.fromsqlraw` | `FromSqlRaw()` with variable | Critical |
| `csharp.ef.executesqlraw` | `ExecuteSqlRaw()` with variable | Critical |
| `csharp.dapper.execute` | `connection.Execute()` with string concat | Critical |
| `csharp.dapper.query` | `connection.Query()` with string concat | Critical |

#### Command Injection (CWE-78)

| ID | Method | Severity |
|---|---|---|
| `csharp.process.start` | `Process.Start()` with variable | Critical |
| `csharp.processstartinfo.filename` | `ProcessStartInfo.FileName` | Critical |
| `csharp.processstartinfo.arguments` | `ProcessStartInfo.Arguments` | Critical |

#### XSS / HTML Output (CWE-79)

| ID | Method | Severity |
|---|---|---|
| `csharp.response.write` | `Response.Write()` | High |
| `csharp.html.raw` | `Html.Raw()` | High |
| `csharp.contentresult` | `ContentResult` with HTML | High |

#### Redirect (CWE-601)

| ID | Method | Severity |
|---|---|---|
| `csharp.redirect` | `Redirect()` / `RedirectPermanent()` | High |

#### File Operations (CWE-22)

| ID | Method | Severity |
|---|---|---|
| `csharp.file.readalltext` | `File.ReadAllText()` | High |
| `csharp.file.writealltext` | `File.WriteAllText()` | High |
| `csharp.file.delete` | `File.Delete()` | High |
| `csharp.path.combine` | `Path.Combine()` with user input | High |
| `csharp.filestream.new` | `new FileStream()` | High |

#### XXE (CWE-611)

| ID | Method | Severity |
|---|---|---|
| `csharp.xmldocument.loadxml` | `XmlDocument.LoadXml()` | High |
| `csharp.xmlreader.create` | `XmlReader.Create()` without DtdProcessing.Prohibit | High |
| `csharp.xmltextreader` | `new XmlTextReader()` | High |

#### SSRF (CWE-918)

| ID | Method | Severity |
|---|---|---|
| `csharp.httpclient.getasync` | `HttpClient.GetAsync()` | High |
| `csharp.httpclient.postasync` | `HttpClient.PostAsync()` | High |
| `csharp.webrequest.create` | `WebRequest.Create()` | High |

#### LDAP Injection (CWE-90)

| ID | Method | Severity |
|---|---|---|
| `csharp.directorysearcher.filter` | `DirectorySearcher.Filter` | High |
| `csharp.directorysearcher.new` | `new DirectorySearcher()` with filter | High |

#### Deserialization (CWE-502)

| ID | Method | Severity |
|---|---|---|
| `csharp.binaryformatter.deserialize` | `BinaryFormatter.Deserialize()` | Critical |
| `csharp.soapformatter.deserialize` | `SoapFormatter.Deserialize()` | Critical |
| `csharp.xmlserializer` | `XmlSerializer` with dynamic type | High |

#### Logging (CWE-117)

| ID | Method | Severity |
|---|---|---|
| `csharp.ilogger.log` | `ILogger.Log*()` methods | Medium |
| `csharp.console.writeline` | `Console.WriteLine()` | Medium |

#### Cryptography (CWE-327, CWE-328)

| ID | Method | Severity |
|---|---|---|
| `csharp.md5.create` | `MD5.Create()` | Medium |
| `csharp.sha1.create` | `SHA1.Create()` | Medium |
| `csharp.des.create` | `DES.Create()` / `TripleDES.Create()` | High |
| `csharp.aes.ecb` | AES with CipherMode.ECB | High |

### Sanitizers (16 tracked)

Sanitizers neutralize tainted data for specific sink categories.

#### SQL Parameterization

| ID | Method | Neutralizes |
|---|---|---|
| `csharp.sqlparameter` | `SqlParameter` / `Parameters.Add()` | SQL query |
| `csharp.ef.fromsqlinterpolated` | `FromSqlInterpolated()` | SQL query |
| `csharp.ef.executesqlinterpolated` | `ExecuteSqlInterpolated()` | SQL query |

#### HTML Encoding

| ID | Method | Neutralizes |
|---|---|---|
| `csharp.htmlencoder.encode` | `HtmlEncoder.Encode()` | HTML output |
| `csharp.webutility.htmlencode` | `WebUtility.HtmlEncode()` | HTML output |
| `csharp.antixss.htmlencode` | `AntiXssEncoder.HtmlEncode()` | HTML output |

#### URL Encoding

| ID | Method | Neutralizes |
|---|---|---|
| `csharp.urlencoder.encode` | `UrlEncoder.Encode()` | Redirect, HTML |

#### Path Traversal Prevention

| ID | Method | Neutralizes |
|---|---|---|
| `csharp.path.getfilename` | `Path.GetFileName()` | File operations |

#### Type Coercion

| ID | Method | Neutralizes |
|---|---|---|
| `csharp.int.parse` | `int.Parse()` / `int.TryParse()` | SQL, command |

#### XXE Prevention

| ID | Method | Neutralizes |
|---|---|---|
| `csharp.dtdprocessing.prohibit` | `DtdProcessing.Prohibit` | XXE |

#### CSRF Protection

| ID | Method | Neutralizes |
|---|---|---|
| `csharp.validateantiforgerytoken` | `[ValidateAntiForgeryToken]` | CSRF |

#### Input Validation

| ID | Method | Neutralizes |
|---|---|---|
| `csharp.modelstate.isvalid` | `ModelState.IsValid` | SQL, command, HTML |

#### Redirect Validation

| ID | Method | Neutralizes |
|---|---|---|
| `csharp.url.islocalurl` | `Url.IsLocalUrl()` | Redirect |

#### Cryptography

| ID | Method | Neutralizes |
|---|---|---|
| `csharp.rfc2898derivebytes` | `Rfc2898DeriveBytes` | Crypto |
| `csharp.passwordhasher` | `PasswordHasher<T>` | Crypto |

#### Deserialization Safety

| ID | Method | Neutralizes |
|---|---|---|
| `csharp.typenamehandling.none` | `TypeNameHandling.None` | Deserialization |

## Rule Coverage

### C#-Specific Rules (10 rules)

Rules in `internal/rules/csharp/csharp.go` that target C#-specific patterns.

| Rule ID | Name | Severity | What It Detects |
|---|---|---|---|
| `GTSS-CS-001` | CSharpSQLInjection | Critical | SQL injection via `SqlCommand`, `CommandText`, `FromSqlRaw`, `ExecuteSqlRaw` with string concatenation or interpolation |
| `GTSS-CS-003` | CSharpInsecureDeserialization | Critical | `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter` deserialization; `JavaScriptSerializer` with `SimpleTypeResolver`; JSON.NET `TypeNameHandling.All/Auto/Objects/Arrays` |
| `GTSS-CS-004` | CSharpCommandInjection | Critical | `Process.Start` with variable arguments, `ProcessStartInfo.FileName`/`Arguments` with dynamic values |
| `GTSS-CS-005` | CSharpPathTraversal | High | `File.*`/`Directory.*` operations and `Path.Combine` with user-controlled paths in ASP.NET controllers |
| `GTSS-CS-006` | CSharpLDAPInjection | High | `DirectorySearcher.Filter` with string concatenation or interpolation |
| `GTSS-CS-008` | CSharpHardcodedConnectionString | High | Connection strings with embedded `Password=` or `Pwd=` in source code |
| `GTSS-CS-009` | CSharpInsecureCookie | Medium | `CookieOptions` missing `Secure`, `HttpOnly`, or `SameSite` flags |
| `GTSS-CS-010` | CSharpCORSMisconfiguration | Medium | `AllowAnyOrigin()` with `AllowCredentials()`, `WithOrigins("*")` wildcard |
| `GTSS-CS-011` | CSharpBlazorJSInteropInjection | High | `JSRuntime.InvokeAsync` with `eval` or string interpolation in function name |
| `GTSS-CS-012` | CSharpMassAssignment | High | `TryUpdateModelAsync<T>` without specifying included properties |

### Cross-Language Rules Covering C#

Rules from other categories that include `LangCSharp` in their language list.

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-INJ-001` | SQLInjection | General SQL injection via string concatenation |
| `GTSS-INJ-002` | CommandInjection | General command injection patterns |
| `GTSS-INJ-004` | LDAPInjection | General LDAP filter concatenation |
| `GTSS-INJ-006` | XPathInjection | XPath queries with string concatenation |
| `GTSS-XXE-004` | CSharpXXE | `XmlTextReader`, `XmlReader.Create` without `DtdProcessing.Prohibit` |
| `GTSS-XSS-008` | ServerSideRenderingXSS | `Html.Raw()` in Razor views |
| `GTSS-DESER-001` | ExtendedDeserialization | `BinaryFormatter`, `LosFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `ObjectStateFormatter`, JSON.NET `TypeNameHandling` |

### Additional LangAny Rules

All rules with `LangAny` apply to C# files. Key categories include:

- **Secrets**: `GTSS-SEC-001` through `GTSS-SEC-006` (hardcoded passwords, API keys, private keys, connection strings, JWT secrets)
- **Traversal**: `GTSS-TRV-001`, `GTSS-TRV-003`, `GTSS-TRV-008` (path traversal, archive extraction, null byte)
- **SSRF**: `GTSS-SSRF-001`, `GTSS-SSRF-002` (URL from user input, internal network access)
- **Authentication**: `GTSS-AUTH-001`, `GTSS-AUTH-003`, `GTSS-AUTH-005`, `GTSS-AUTH-007` (hardcoded credentials, CORS wildcard, weak passwords, privilege escalation patterns)
- **Generic**: `GTSS-GEN-001` through `GTSS-GEN-005`, `GTSS-GEN-012` (debug mode, deserialization, XXE, open redirect, log injection, insecure download patterns)
- **Misconfiguration**: `GTSS-MISC-003` (missing security headers)
- **Validation**: `GTSS-VAL-005` (file upload hardening)

## Example Detections

### SQL Injection via Entity Framework FromSqlRaw

GTSS flags `FromSqlRaw()` with string interpolation instead of the safe `FromSqlInterpolated()`:

```csharp
// DETECTED: GTSS-CS-001 + taint flow csharp.fromquery -> csharp.ef.fromsqlraw
[HttpGet("search")]
public IActionResult Search([FromQuery] string email)
{
    var sql = $"SELECT * FROM Users WHERE Email = '{email}'";
    var users = _context.Users.FromSqlRaw(sql).ToList();
    return Ok(users);
}
```

### Insecure Deserialization with BinaryFormatter

GTSS detects use of `BinaryFormatter` which Microsoft recommends against for untrusted data:

```csharp
// DETECTED: GTSS-CS-003
[HttpPost("import")]
public IActionResult Import()
{
    var formatter = new BinaryFormatter();
    var obj = formatter.Deserialize(Request.Body);
    return Ok(obj);
}
```

### Blazor JS Interop Injection

GTSS catches `eval` calls through JSRuntime which can lead to XSS:

```csharp
// DETECTED: GTSS-CS-011
public async Task ExecuteCode(string userCode)
{
    await JSRuntime.InvokeAsync<string>("eval", userCode);
}
```

### CORS Misconfiguration

GTSS detects `AllowAnyOrigin()` combined with `AllowCredentials()`:

```csharp
// DETECTED: GTSS-CS-010
services.AddCors(options =>
{
    options.AddPolicy("MyPolicy", builder =>
    {
        builder.AllowAnyOrigin()
               .AllowCredentials()
               .AllowAnyMethod();
    });
});
```

## Safe Patterns

### Parameterized SQL with SqlParameter

GTSS recognizes `SqlParameter` as a sanitizer that neutralizes SQL injection:

```csharp
// SAFE: SqlParameter neutralizes SQL injection
var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
cmd.Parameters.AddWithValue("@name", name);
cmd.ExecuteReader();
```

### Entity Framework FromSqlInterpolated

GTSS recognizes `FromSqlInterpolated()` as safe (it auto-parameterizes):

```csharp
// SAFE: FromSqlInterpolated handles parameterization automatically
var users = _context.Users
    .FromSqlInterpolated($"SELECT * FROM Users WHERE Email = {email}")
    .ToList();
```

### Path Traversal Prevention with GetFileName

GTSS recognizes `Path.GetFileName()` as a sanitizer for file path operations:

```csharp
// SAFE: Path.GetFileName strips directory components
var safeName = Path.GetFileName(filename);
var path = Path.Combine("/uploads", safeName);
var content = File.ReadAllText(path);
```

### Secure Cookie Configuration

GTSS does not flag cookies with all security flags set:

```csharp
// SAFE: all security flags present
var options = new CookieOptions {
    Secure = true,
    HttpOnly = true,
    SameSite = SameSiteMode.Strict,
    Expires = DateTimeOffset.UtcNow.AddHours(8)
};
Response.Cookies.Append("session", token, options);
```

## Test Fixtures

Located in `testdata/fixtures/csharp/`:

### Vulnerable Fixtures (10)

| File | Vulnerabilities Demonstrated |
|---|---|
| `SqlInjection.cs` | SqlCommand concat, FromSqlRaw interpolation, ExecuteSqlRaw concat |
| `CommandInjection.cs` | Process.Start with user input, ProcessStartInfo with dynamic args |
| `XssReflected.cs` | Response.WriteAsync, Html.Raw, Response.Write with user input |
| `PathTraversal.cs` | File.ReadAllText, File.WriteAllText, File.Delete with user paths |
| `Deserialization.cs` | BinaryFormatter, SoapFormatter, TypeNameHandling.All |
| `LDAPInjection.cs` | DirectorySearcher.Filter with concat and interpolation |
| `HardcodedConnString.cs` | Connection strings with embedded Password/Pwd |
| `InsecureCookie.cs` | CookieOptions without security flags |
| `CORSMisconfig.cs` | AllowAnyOrigin with AllowCredentials |
| `BlazorJSInterop.cs` | JSRuntime eval, string interpolation in function name |
| `MassAssignment.cs` | TryUpdateModelAsync without field restrictions |

### Safe Fixtures (8)

| File | Safe Patterns Demonstrated |
|---|---|
| `SqliParameterized.cs` | SqlParameter, FromSqlInterpolated, ExecuteSqlInterpolated |
| `CommandSafe.cs` | Input validation with regex allowlist before Process.Start |
| `XssEncoded.cs` | HtmlEncoder, WebUtility.HtmlEncode |
| `PathSafe.cs` | Path.GetFileName, Path.GetFullPath with StartsWith validation |
| `DeserSafe.cs` | System.Text.Json, TypeNameHandling.None |
| `CookieSafe.cs` | CookieOptions with Secure, HttpOnly, SameSite |
| `CORSSafe.cs` | WithOrigins with explicit domain list |
| `ConnStringSafe.cs` | Connection strings from IConfiguration and environment variables |

## Limitations

- **Razor files**: `.cshtml` and `.razor` file extensions are not mapped in the language detector. Razor-specific patterns (like `@Html.Raw()`) are detected when they appear in `.cs` files via the XSS cross-language rule, but standalone Razor view files are not scanned.
- **Blazor component lifecycle**: Blazor component lifecycle methods (`OnInitializedAsync`, `OnParametersSetAsync`) are not tracked as sources. Only JSRuntime calls are specifically checked.
- **SignalR**: SignalR hub methods are not tracked as sources of user input.
- **.NET MAUI**: Mobile-specific patterns (insecure storage, certificate pinning bypass) are not covered.
- **Minimal API**: .NET 6+ minimal API patterns (`app.MapGet`, `app.MapPost` with lambda handlers) are not specifically tracked as user input sources.
- **LINQ injection**: LINQ expressions built with dynamic predicates (e.g., `Dynamic LINQ` library) are not detected.
- **Entity Framework migrations**: Database migration files are not scanned for insecure schema changes.
- **NuGet dependencies**: Package references in `.csproj` files are not scanned for known vulnerable dependencies.
- **gRPC**: gRPC service methods are not tracked as user input sources.
- **Windows-specific**: Windows-specific patterns (registry access, COM interop, P/Invoke) are not covered.
