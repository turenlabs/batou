# Batou Rule Evasion Analysis Report

**Date:** 2026-02-10
**Scope:** All 11 rule categories (55+ individual rules)
**Purpose:** Identify weaknesses in regex-based detection to harden Batou before production deployment

---

## Table of Contents

1. [Injection Rules (BATOU-INJ-001 through INJ-007)](#1-injection-rules)
2. [XSS Rules (BATOU-XSS-001 through XSS-011)](#2-xss-rules)
3. [Path Traversal Rules (BATOU-TRV-001 through TRV-009)](#3-path-traversal-rules)
4. [Cryptography Rules (BATOU-CRY-001 through CRY-011)](#4-cryptography-rules)
5. [Secrets Rules (BATOU-SEC-001 through SEC-006)](#5-secrets-rules)
6. [SSRF Rules (BATOU-SSRF-001 through SSRF-004)](#6-ssrf-rules)
7. [Auth Rules (BATOU-AUTH-001 through AUTH-006)](#7-auth-rules)
8. [Generic Rules (BATOU-GEN-001 through GEN-009)](#8-generic-rules)
9. [Logging Rules (BATOU-LOG-001 through LOG-003)](#9-logging-rules)
10. [Validation Rules (BATOU-VAL-001 through VAL-004)](#10-validation-rules)
11. [Memory Rules (BATOU-MEM-001 through MEM-006)](#11-memory-rules)
12. [Cross-Cutting Evasion Techniques](#12-cross-cutting-evasion-techniques)
13. [Summary and Risk Matrix](#13-summary-and-risk-matrix)

---

## 1. Injection Rules

### BATOU-INJ-001: SQL Injection

**Detection mechanism:** Matches SQL keywords (SELECT, INSERT, UPDATE, DELETE, etc.) inside string formatting/concatenation patterns (fmt.Sprintf, f-strings, .format(), `+` concat, template literals, PHP `$var`, Ruby `#{}`)

**Evasion techniques:**

1. **Multi-line query construction (HIGH likelihood in AI code)**
   ```python
   query = "SELECT * FROM users WHERE id = "
   query += user_id  # Concat on separate line - regex checks per-line only
   cursor.execute(query)
   ```
   The regex `reSQLConcatGeneric` requires the SQL keyword AND the `+` operator on the same line. Splitting them across lines evades detection entirely.

2. **Indirect variable assignment (HIGH likelihood)**
   ```go
   base := "SELECT * FROM users WHERE name = '%s'"
   q := fmt.Sprintf(base, userInput)
   ```
   The regex `reSQLSprintfGo` requires the SQL keyword inside the `fmt.Sprintf` string literal on the same line. Storing the format string in a variable first evades detection.

3. **ORM raw query methods with non-standard names (MEDIUM likelihood)**
   ```python
   db.session.execute(text(f"SELECT * FROM users WHERE id = {uid}"))
   ```
   The pattern `reSQLExecConcatPy` only matches `cursor|conn|connection|db` prefixes. Using `session.execute`, `engine.execute`, or custom DB wrapper names evades detection.

**Hardening fixes:**
- Implement multi-line joining for SQL keyword + concat detection (join adjacent lines within a window)
- Track variable assignments carrying SQL keywords and flag when those variables are used in format functions
- Expand the list of DB execution method prefixes to include `session`, `engine`, `pool`, and common ORM patterns

---

### BATOU-INJ-002: Command Injection

**Detection mechanism:** Matches `os.system`, `subprocess` with `shell=True`, `exec.Command("sh", "-c")`, `child_process.exec`, `Runtime.exec`, etc.

**Evasion techniques:**

1. **Indirect shell invocation via wrapper function (HIGH likelihood in AI code)**
   ```python
   def run_command(cmd):
       import subprocess
       return subprocess.call(cmd, shell=True)

   run_command(user_input)  # Not detected - the shell=True is in a different function
   ```
   The regex only matches `subprocess.call` with `shell=True` on the same line. Wrapping in a helper function evades detection.

2. **Using os.popen via variable reference (MEDIUM likelihood)**
   ```python
   executor = os.popen
   executor(user_input)
   ```
   The regex requires the literal `os.popen(` prefix. Assigning the function to a variable breaks the pattern match.

3. **Go exec.Command with variable shell name (MEDIUM likelihood)**
   ```go
   shell := "/bin/bash"
   flag := "-c"
   exec.Command(shell, flag, userInput)
   ```
   The regex `reCmdExecCommandShell` requires string literals `"sh"`, `"bash"`, etc. as the first arg. Using variables evades detection.

**Hardening fixes:**
- Track `shell=True` across function definitions (inter-procedural, limited scope)
- Add pattern for function-reference aliases of dangerous calls
- Flag `exec.Command` with non-literal first arguments more aggressively

---

### BATOU-INJ-003: Code Injection

**Detection mechanism:** Matches `eval()`, `exec()`, `new Function()`, `compile()`, `setTimeout/setInterval` with string arg.

**Evasion techniques:**

1. **Aliasing eval (HIGH likelihood in AI code)**
   ```javascript
   const execute = eval;
   execute(userInput);
   ```
   ```python
   fn = eval
   fn(user_input)
   ```
   The regex requires the literal `eval(` token. Assigning `eval` to another name completely evades detection.

2. **globalThis/window bracket access (MEDIUM likelihood)**
   ```javascript
   globalThis["ev" + "al"](userInput);
   window["eval"](userInput);
   ```
   No regex matches bracket-notation dynamic property access to reach `eval`.

3. **Python exec via builtins (MEDIUM likelihood)**
   ```python
   import builtins
   getattr(builtins, 'exec')(user_input)
   ```
   The regex only matches the literal `exec(` call. Using `getattr` to dynamically resolve `exec` evades detection.

**Hardening fixes:**
- Detect assignment of `eval`/`exec` to variables: `\b\w+\s*=\s*eval\b`
- Detect bracket-notation access: `(window|globalThis|self)\[.*eval.*\]`
- Detect `getattr(builtins, ...)` patterns

---

### BATOU-INJ-004: LDAP Injection

**Evasion techniques:**

1. **Building LDAP filter in multiple steps (HIGH likelihood)**
   ```python
   base_filter = "(uid="
   search_filter = base_filter + username + ")"
   conn.search(search_filter)
   ```
   The regex `reLDAPFormat` requires both the LDAP library call and the format pattern on the same line.

2. **Using non-standard LDAP library names (MEDIUM likelihood)**
   ```python
   from ldap3 import Server, Connection
   c = Connection(server)
   c.search("dc=example", f"(uid={user_input})")
   ```
   The regex looks for `ldap|ldap3|python-ldap` prefix on the search call. A variable like `c` doesn't match.

**Hardening:** Track LDAP filter variables across lines; expand detection to any `.search()` call with format-string arguments that contain LDAP filter syntax `(`, `=`.

---

### BATOU-INJ-005: Template Injection (SSTI)

**Evasion techniques:**

1. **Passing variable through intermediate assignment (HIGH likelihood)**
   ```python
   template_str = request.args.get('template')
   result = render_template_string(template_str)
   ```
   Wait -- this would actually be detected because `render_template_string(template_str)` matches `render_template_string\s*\(\s*[^"'\s)]`. The first arg is a non-string-literal variable. This is correctly detected.

   However, this evades:
   ```python
   tmpl = Template
   t = tmpl(user_input)
   ```
   The regex requires the literal `Template(` token. Aliasing the class evades detection.

2. **Using Jinja2 Environment directly (MEDIUM likelihood)**
   ```python
   env = jinja2.Environment()
   template = env.from_string(user_input)  # Detected by reTemplateFromString
   ```
   This IS detected. But:
   ```python
   env = jinja2.Environment()
   loader = env.get_template  # Not from_string, but get_template with a path
   ```
   Using `env.parse()` or `env.overlay()` would not be detected.

**Hardening:** Detect `jinja2.Environment` construction combined with any rendering of user input. Track Template class aliases.

---

### BATOU-INJ-006: XPath Injection

**Evasion techniques:**

1. **Using lxml-specific API names (MEDIUM likelihood)**
   ```python
   tree.xpath(f"//user[@name='{user_input}']")
   ```
   This IS detected by `reXPathFormat` (matches `xpath` + `f"'`).

   But:
   ```python
   from lxml import etree
   result = etree.XPath(f"//user[@name='{user_input}']")
   ```
   `etree.XPath()` is not in the pattern list (only `xpath|selectNodes|selectSingleNode|evaluate|querySelector`).

2. **Multi-line XPath construction (HIGH likelihood)**
   ```python
   expr = "//user[@name='" + user_input + "']"
   tree.xpath(expr)
   ```
   The xpath call and concatenation are on different lines, evading per-line detection.

**Hardening:** Add `etree.XPath` to the pattern list. Implement multi-line tracking for XPath query construction.

---

### BATOU-INJ-007: NoSQL Injection

**Evasion techniques:**

1. **Using query builder with unsanitized variables (HIGH likelihood in AI code)**
   ```javascript
   const filter = {};
   filter[req.body.field] = req.body.value;
   db.collection.find(filter);
   ```
   The regex looks for `$where`, `$regex`, `JSON.parse` in `.find()`, or string concatenation. Dynamically building a filter object with bracket notation is not detected.

2. **Passing entire req.body as MongoDB query (HIGH likelihood)**
   ```javascript
   app.get('/search', (req, res) => {
     db.collection('users').find(req.query).toArray();
   });
   ```
   The regex `reNoSQLQueryConcat` looks for string concat or specific operators in the `.find()` call. Passing `req.query` directly as the query object is not detected, even though it's the most common NoSQL injection vector.

3. **Using MongoDB aggregation pipeline with user input (MEDIUM likelihood)**
   ```javascript
   const pipeline = [{ $match: req.body }];
   db.collection.aggregate(pipeline);
   ```
   The regex only checks `.aggregate(` for function/arrow content (for mapReduce), not for direct user input pass-through.

**Hardening:** This is a critical gap. Add detection for `req.body`/`req.query`/`req.params` passed directly to MongoDB query methods. Detect dynamic filter construction via bracket notation.

---

## 2. XSS Rules

### BATOU-XSS-001: innerHTML Assignment

**Detection mechanism:** Matches `.innerHTML =` or `.outerHTML =` where the RHS is not a static string literal.

**Evasion techniques:**

1. **Using insertAdjacentHTML (HIGH likelihood in AI code)**
   ```javascript
   element.insertAdjacentHTML('beforeend', userInput);
   ```
   No regex matches `insertAdjacentHTML`. This is functionally identical to innerHTML assignment.

2. **Using jQuery .html() (HIGH likelihood)**
   ```javascript
   $('#container').html(userInput);
   ```
   No regex matches jQuery's `.html()` method, which is equivalent to innerHTML.

3. **Using append/prepend with HTML strings (MEDIUM likelihood)**
   ```javascript
   element.append(document.createRange().createContextualFragment(userInput));
   ```
   `createContextualFragment` parses HTML and is not detected.

**Hardening:** Add patterns for `insertAdjacentHTML`, `.html(`, `.append(` with HTML content, and `createContextualFragment`.

---

### BATOU-XSS-002: dangerouslySetInnerHTML

**Detection mechanism:** Matches `dangerouslySetInnerHTML={{ `.

**Evasion techniques:**

1. **Spreading props with dangerouslySetInnerHTML inside (MEDIUM likelihood)**
   ```jsx
   const props = { dangerouslySetInnerHTML: { __html: userInput } };
   return <div {...props} />;
   ```
   The regex requires `dangerouslySetInnerHTML=` on the JSX element. Spreading from an object evades detection.

2. **Multi-line formatting (LOW likelihood -- mostly cosmetic)**
   ```jsx
   <div
     dangerouslySetInnerHTML={
       { __html: data }
     }
   />
   ```
   The regex requires `dangerouslySetInnerHTML\s*=\s*\{\s*\{` on one line. Multi-line JSX formatting could evade this, though most formatters keep it on one line.

**Hardening:** Also match `dangerouslySetInnerHTML` as a standalone property name (even without `=`), then check context.

---

### BATOU-XSS-004: Unescaped Template Output

**Evasion techniques:**

1. **Django/Jinja2 custom template tags (MEDIUM likelihood)**
   ```html
   {% autoescape off %}{{ user_input }}{% endautoescape %}
   ```
   This IS detected by `reJinjaAutoescOff`. But custom template tags that output raw HTML:
   ```python
   # In templatetags/custom.py
   @register.simple_tag
   def raw_output(value):
       return mark_safe(value)
   ```
   Then `{% raw_output user_input %}` in templates would not be detected.

2. **Go template with custom FuncMap (MEDIUM likelihood)**
   ```go
   funcMap := template.FuncMap{"trust": func(s string) template.HTML { return template.HTML(s) }}
   ```
   The regex only detects `template.HTML(` calls. Custom functions that wrap `template.HTML` are not detected at the call site.

**Hardening:** Detect `mark_safe` usage (already done in XSS-008). Track FuncMap entries that return `template.HTML`.

---

### BATOU-XSS-011: Reflected XSS

**Evasion techniques:**

1. **Intermediate variable between request param and response (HIGH likelihood)**
   ```python
   name = request.args.get('name')
   return f"<h1>Hello {name}</h1>"
   ```
   The regex `rePyReflected` requires `request.args` in the return/response line itself. Assigning to an intermediate variable evades detection.

2. **Go handler writing to ResponseWriter indirectly (HIGH likelihood)**
   ```go
   name := r.URL.Query().Get("name")
   msg := "<h1>Hello " + name + "</h1>"
   w.Write([]byte(msg))
   ```
   The regex `reGoReflected` requires `fmt.Fprintf(w` with `r.URL.Query` on the same line. Using `w.Write` with a pre-built string evades detection.

**Hardening:** Track taint from request param variables. If a variable is assigned from `request.args.get()` or `r.URL.Query().Get()`, flag when that variable flows into response writing within the same function scope.

---

## 3. Path Traversal Rules

### BATOU-TRV-001: Path Traversal

**Detection mechanism:** Matches file operations (os.Open, open(), fs.readFile, etc.) with variable arguments, suppressed if `filepath.Clean` + `strings.HasPrefix` are nearby.

**Evasion techniques:**

1. **Using filepath.Clean WITHOUT prefix check (HIGH likelihood in AI code)**
   ```go
   cleanPath := filepath.Clean(userInput)
   data, _ := os.ReadFile(cleanPath) // Still traversable!
   ```
   The guard check `hasTraversalGuard` requires BOTH `filepath.Clean` AND `strings.HasPrefix`. However, AI-generated code frequently uses Clean alone thinking it's sufficient. This IS correctly detected since both are required. Good.

   But there's a gap: the guard check looks for `filepath.Clean` OR `filepath.Abs` OR `os.path.realpath` as the "clean" step. If code uses a custom sanitizer name:
   ```go
   safePath := sanitizePath(userInput) // custom function
   data, _ := os.ReadFile(safePath)
   ```
   This would trigger a false positive (no recognized guard), but the inverse is important: no evasion here.

2. **Using path/filepath operations that bypass the detection variable pattern (MEDIUM likelihood)**
   ```go
   f, err := os.Open(filepath.Join(baseDir, r.URL.Query().Get("file")))
   ```
   The regex `goFileOpUserInput` matches `os.Open\s*\(\s*[a-zA-Z_]\w*` -- it requires a simple variable name as the first arg. When the arg is a function call like `filepath.Join(...)`, the `[a-zA-Z_]\w*` pattern actually matches `filepath` (the start of `filepath.Join`). So this IS detected. Good.

3. **Python os.path.join where user input is not from request.* (HIGH likelihood)**
   ```python
   filename = get_filename_from_user()  # Custom function
   path = os.path.join('/uploads', filename)
   f = open(path)
   ```
   The regex `pyOpenUserInput` only matches specific variable names: `request.`, `user_input`, `filename`, `file_path`, `path`, `name`. The `pyOsPathJoin` only matches when `request.|user_input|input|param|arg` appears in the join arguments. Using a custom getter function with a non-matching variable name could evade detection.

**Hardening:** For Python path traversal, broaden detection to any `open()` call with a non-literal first argument, then use context-based suppression for safety checks.

---

### BATOU-TRV-003: Archive Extraction (Zip Slip)

**Evasion techniques:**

1. **Python tarfile.extract() instead of extractall() (HIGH likelihood)**
   ```python
   with tarfile.open('archive.tar.gz') as tar:
       for member in tar.getmembers():
           tar.extract(member, path='/output')
   ```
   The regex `pyExtractAll` only matches `.extractall(`. Individual `.extract()` calls in a loop are not detected, even though they're equally vulnerable to zip-slip if member names aren't validated.

2. **Go: manual file extraction without os.Create (MEDIUM likelihood)**
   ```go
   outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE, 0644)
   ```
   The regex `goCreateFromZip` specifically matches `os.Create(` with path variable patterns. Using `os.OpenFile` instead evades detection.

**Hardening:** Add `\.extract\(` (non-extractall) for Python tarfile. Add `os.OpenFile` to Go archive extraction patterns.

---

### BATOU-TRV-006: Prototype Pollution via Spread

**Detection mechanism:** Matches `{ ...req.body }` and `Object.assign({}, req.body)`.

**Evasion techniques:**

1. **Intermediate variable (HIGH likelihood)**
   ```javascript
   const data = req.body;
   const user = { ...data };
   ```
   The regex requires the literal `req.body` in the spread. Assigning to an intermediate variable evades detection.

2. **Deep merge libraries (MEDIUM likelihood)**
   ```javascript
   const _ = require('lodash');
   _.merge(target, req.body);
   ```
   Neither `_.merge` nor `_.assign` are detected. These are equally dangerous for prototype pollution.

**Hardening:** Track `req.body` assignment to variables and flag spreads of those variables. Add patterns for `lodash.merge`, `Object.assign` with req.body in non-first position, and `_.defaultsDeep`.

---

## 4. Cryptography Rules

### BATOU-CRY-001: Weak Hashing

**Detection mechanism:** Matches language-specific MD5/SHA-1 calls (e.g., `md5.New`, `hashlib.md5`, `crypto.createHash('md5')`).

**Evasion techniques:**

1. **Using third-party hashing libraries (MEDIUM likelihood)**
   ```python
   from Crypto.Hash import MD5
   h = MD5.new()
   h.update(password.encode())
   ```
   The regex `rePyMD5` only matches `hashlib.md5(`. PyCryptodome's `MD5.new()` is not detected.

2. **Dynamic hash algorithm selection (MEDIUM likelihood)**
   ```python
   algo = 'md5'
   h = hashlib.new(algo)
   ```
   The regex requires the literal `hashlib.md5(`. Using `hashlib.new()` with a variable algorithm name evades detection.

3. **Importing and aliasing (LOW likelihood)**
   ```go
   import "crypto/md5"
   hasher := md5.New
   h := hasher()
   ```
   The regex requires `md5.New` or `md5.Sum` as the matched token. Storing the function reference evades detection.

**Hardening:** Add `hashlib.new\(.*md5|sha1` pattern. Add PyCryptodome patterns (`MD5.new`, `SHA.new`). Detect `crypto.createHash` with variable argument.

---

### BATOU-CRY-003: Weak Cipher

**Detection mechanism:** Matches DES, RC4, Blowfish function calls and ECB mode keyword.

**Evasion techniques:**

1. **Generic weak cipher regex over-matches (FALSE POSITIVE risk)**
   ```go
   // This describes the DES algorithm
   description := "We migrated from DES to AES-256-GCM"
   ```
   The generic `reWeakCipher` pattern matches the word `DES` in any context (variables, strings, comments that start with `*` or non-standard comment markers). The comment filter only checks for `//`, `#`, `*` prefixes.

2. **Using cipher by numeric identifier (MEDIUM likelihood)**
   ```java
   // javax.crypto
   Cipher c = Cipher.getInstance("DESede/ECB/PKCS5Padding");
   ```
   Wait, this IS detected because the regex matches `Cipher.getInstance("DES`. But:
   ```java
   String algo = "DESede/ECB/PKCS5Padding";
   Cipher c = Cipher.getInstance(algo);
   ```
   Using a variable for the algorithm name evades the `reJavaDES` regex.

**Hardening:** Detect `Cipher.getInstance` with variable arguments, then check if the variable was assigned a weak cipher string nearby.

---

### BATOU-CRY-004: Hardcoded IV

**Detection mechanism:** Matches variable names containing `iv` or `nonce` assigned to byte arrays, strings, or byte literals.

**Evasion techniques:**

1. **Non-standard variable naming (HIGH likelihood in AI code)**
   ```go
   initializationVector := []byte{0x00, 0x01, 0x02, ...}
   // or
   ivec := []byte{0x00, 0x01, 0x02, ...}
   ```
   The regex `reGoByteIV` matches `(?i)\b(iv|nonce)\s*[:=]\s*\[\]byte\s*\{`. The variable must contain exactly `iv` or `nonce` as a word. `initializationVector` contains `iv` as a substring but the `\b` boundary won't match mid-word. Wait -- actually `(?i)\b(iv|nonce)` would NOT match `initializationVector` because `\biv` requires a word boundary before `iv`, which IS present at the start of `initializationVector`. Actually no -- `\binitializationVector` -- the `\b` is before the `i` of `initialization`, not before `iv`. So `\biv\b` would not match inside `initializationVector`. But the pattern is `\b(iv|nonce)` WITHOUT a trailing `\b`, so it would match `iv` at the START of `ivec` (since `\biv` matches at word boundary). But NOT inside `initializationVector`.

   A more evasive name:
   ```python
   cipher_init_vec = b'\x00\x01\x02...'
   ```
   This would not match `\b(iv|nonce)` at all.

2. **Reading IV from a constant defined elsewhere (HIGH likelihood)**
   ```go
   const fixedIV = "0123456789abcdef"  // Detected (matches reStringIV)
   // But in another file:
   iv := config.GetIV()  // Where GetIV returns a hardcoded value
   ```
   Cross-file constant references are not detected.

**Hardening:** Expand IV variable name patterns to include `init.*vec`, `cipher_iv`, `aes_iv`, `encryption_iv`, etc.

---

### BATOU-CRY-005: Insecure TLS

**Detection mechanism:** Matches `InsecureSkipVerify: true`, `verify=False`, `rejectUnauthorized: false`, etc.

**Evasion techniques:**

1. **Setting via variable (HIGH likelihood in AI code)**
   ```go
   skipVerify := true
   tlsConfig := &tls.Config{InsecureSkipVerify: skipVerify}
   ```
   The regex requires `InsecureSkipVerify\s*:\s*true` literally. Using a variable evades detection.

2. **Conditional TLS skip based on environment (MEDIUM likelihood)**
   ```python
   verify = os.environ.get('VERIFY_SSL', 'false').lower() == 'true'
   requests.get(url, verify=verify)
   ```
   The regex requires `verify\s*=\s*False` literally. Using a variable evades detection, even though the default is insecure.

**Hardening:** Flag `InsecureSkipVerify:` with any non-`false` RHS. Flag `verify=` with variable RHS and warn to verify. Track boolean variable assignments used in TLS config.

---

## 5. Secrets Rules

### BATOU-SEC-001: Hardcoded Passwords

**Detection mechanism:** Matches variable names like `password`, `secret`, `api_key`, etc. assigned to string literals, with entropy and placeholder filtering.

**Evasion techniques:**

1. **Non-standard variable names (HIGH likelihood in AI code)**
   ```python
   db_pass = "SuperSecret123!"
   db_pw = "SuperSecret123!"
   credentials = "SuperSecret123!"
   ```
   The `secretVarNames` pattern is `(password|passwd|pwd|pass|secret|api_key|apikey|token|auth_token|access_token|private_key)`. Variables like `db_pass` DO match (contains `pass`). But `credentials` does NOT match, nor does `db_pw`, `login_key`, `master_phrase`, etc.

2. **Configuration struct/dict with secret values (HIGH likelihood)**
   ```go
   config := map[string]string{
       "database_password": "SuperSecret123!",
   }
   ```
   The regex matches `password\s*[:=]=?\s*"value"` and the key-value assignment here has `"database_password":` which does match `password\s*[:=]` since there's a `:` after `password`. This IS detected.

   But:
   ```javascript
   const config = {
     dbCredential: "SuperSecret123!"
   };
   ```
   `dbCredential` does not match any secret variable name pattern.

3. **Base64-encoded secrets (MEDIUM likelihood)**
   ```python
   encoded_key = "U3VwZXJTZWNyZXQxMjMh"  # base64 of "SuperSecret123!"
   secret = base64.b64decode(encoded_key)
   ```
   The first line: `encoded_key` does not match the secret variable name pattern (it contains `key`! Actually, looking at the pattern: `api_key|apikey` -- plain `key` is NOT in the list). Wait: `api_key` matches but plain `key` does not. So `encoded_key` would NOT be detected.

**Hardening:** Add `credential`, `cred`, `key` (with word boundary), `passphrase`, `auth`, `signing_key` to the secret variable name patterns. Add base64 detection for high-entropy strings assigned to variables near decode calls.

---

### BATOU-SEC-002: API Key Exposure

**Detection mechanism:** Known provider prefixes (AKIA for AWS, ghp_ for GitHub, sk_live_ for Stripe, etc.) plus generic high-entropy patterns.

**Evasion techniques:**

1. **Split key across variables (LOW likelihood but possible)**
   ```python
   prefix = "AKIA"
   suffix = "XXXXXXXXXXXXXXXX"
   aws_key = prefix + suffix
   ```
   The regex requires the full pattern `AKIA[0-9A-Z]{16}` on one line. Splitting defeats this.

2. **Keys from newer providers not in the pattern list (MEDIUM likelihood)**
   Anthropic API keys (`sk-ant-...`), OpenAI keys (`sk-...`), Cloudflare tokens, Datadog keys, etc. are not in the known provider list.

3. **Generic API key with low entropy (edge case)**
   ```python
   api_key = "my-simple-api-key-value"
   ```
   The generic pattern requires Shannon entropy >= 3.5 AND 3+ character classes. Simple human-readable keys may not meet the entropy threshold.

**Hardening:** Add patterns for Anthropic (`sk-ant-`), OpenAI (`sk-`), Cloudflare, and other popular AI/cloud provider key formats. Lower entropy threshold for variables explicitly named `api_key` or `secret`.

---

### BATOU-SEC-003: Private Key in Code

**Detection mechanism:** Matches `-----BEGIN ... PRIVATE KEY-----` header.

**Evasion techniques:**

1. **PKCS#8 format without algorithm prefix (LOW likelihood)**
   ```
   -----BEGIN PRIVATE KEY-----
   ```
   The regex is `-----BEGIN\s+(RSA |EC |DSA |OPENSSH |ED25519 )?PRIVATE KEY-----`. The `?` makes the algorithm prefix optional, so plain `BEGIN PRIVATE KEY` IS matched. This is robust.

2. **Base64-encoded PEM block (LOW likelihood)**
   ```python
   key_data = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ=="  # base64 of the header
   ```
   Base64-encoded PEM headers would not be detected.

3. **Key loaded from environment variable reference that looks like a placeholder (potential false negative)**
   ```python
   private_key = os.environ.get('PRIVATE_KEY', '-----BEGIN RSA PRIVATE KEY-----\n...')
   ```
   The default value contains the PEM header, so it IS detected. However the developer may argue it's a fallback. The scanner should still flag this.

**Hardening:** Add base64 pattern detection for PEM headers. This is low priority since base64-encoded keys in source are rare.

---

### BATOU-SEC-004: Connection Strings

**Evasion techniques:**

1. **Placeholder values in non-standard format (MEDIUM likelihood)**
   ```python
   dsn = "postgresql://admin:Str0ngP@ss!@db.example.com:5432/mydb"
   ```
   The placeholder filter checks for `username:password@`, `user:pass@`, `<password>`, `${`, etc. A real-looking credential like `admin:Str0ngP@ss!` would NOT match any placeholder pattern and IS correctly flagged.

2. **Connection string via environment with hardcoded fallback (MEDIUM likelihood)**
   ```python
   dsn = os.environ.get('DATABASE_URL', 'postgresql://user:secret@localhost/db')
   ```
   The `${` check in the placeholder filter would not trigger here. The string contains `user:secret@` which does not match the placeholder `user:pass@` or `username:password@` exactly. So this IS detected. However `localhost` might make it seem like a dev-only credential.

**Hardening:** Add `localhost`/`127.0.0.1` as a factor that reduces severity (but doesn't suppress) for connection strings.

---

## 6. SSRF Rules

### BATOU-SSRF-001: URL from User Input

**Detection mechanism:** Matches HTTP client calls (http.Get, requests.get, fetch, axios, etc.) with a variable (non-literal) argument, suppressed if URL validation patterns are found nearby.

**Evasion techniques:**

1. **Custom HTTP client wrapper (HIGH likelihood in AI code)**
   ```python
   def make_request(url):
       return requests.get(url)

   make_request(user_provided_url)  # Not detected at call site
   ```
   The regex only matches `requests.get(variable)` directly. A wrapper function hides the HTTP call from the detection point where user input enters.

2. **Validation check that doesn't actually validate (MEDIUM likelihood)**
   ```go
   parsedURL := url.Parse(userInput)  // Matches "parseurl" validation indicator
   resp, _ := http.Get(parsedURL.String())
   ```
   The `hasURLValidation` function suppresses findings if it sees `parseurl` or `url.parse` nearby. But `url.Parse` alone doesn't validate against SSRF -- it just parses the URL. The scanner incorrectly suppresses the finding.

3. **Using httpx/aiohttp with non-matched variable patterns (MEDIUM likelihood)**
   ```python
   async with aiohttp.ClientSession() as session:
       resp = await session.get(user_url)
   ```
   The regex `pyHttpClient` matches `(?:httpx|aiohttp)\.\w+\.\w+\s*\(\s*[a-zA-Z_]`. The pattern `session.get(` doesn't match because `session` is not `aiohttp.something.something`. The `aiohttp.ClientSession` is on a different line.

**Hardening:** Tighten validation suppression -- `url.Parse` alone should NOT suppress; require both parsing AND IP/host validation. Add `session.get` as an SSRF-relevant pattern for aiohttp.

---

### BATOU-SSRF-002: Internal Network Access

**Evasion techniques:**

1. **Decimal/octal/hex IP encoding (HIGH likelihood for targeted attacks)**
   ```
   http://2130706433     # decimal for 127.0.0.1
   http://0x7f000001     # hex for 127.0.0.1
   http://0177.0.0.1     # octal
   http://127.1           # short form
   ```
   The regex `internalIPLiteral` only matches standard dotted decimal notation. Alternative IP encodings bypass the detection completely.

2. **IPv6 representations (MEDIUM likelihood)**
   ```
   http://[::ffff:127.0.0.1]
   http://[0:0:0:0:0:ffff:7f00:1]
   ```
   The regex only matches `\[::1\]` for IPv6. IPv4-mapped IPv6 addresses are not detected.

3. **DNS names that resolve to internal IPs (HIGH likelihood)**
   ```python
   requests.get("http://internal.company.com")  # Resolves to 10.0.0.5
   requests.get("http://attacker.com")  # DNS rebinding to 169.254.169.254
   ```
   The scanner only checks for literal IP addresses and `localhost`. DNS names that resolve to internal IPs are not detectable by regex.

**Hardening:** Add decimal, hex, and octal IP formats. Add IPv4-mapped IPv6 patterns. Note: DNS-based SSRF requires runtime validation, not static analysis -- document this limitation clearly.

---

## 7. Auth Rules

### BATOU-AUTH-001: Hardcoded Credential Check

**Detection mechanism:** Matches `password == "literal"` or `username === "admin"` patterns.

**Evasion techniques:**

1. **Comparing against a constant (HIGH likelihood in AI code)**
   ```python
   ADMIN_PASSWORD = "secret123"
   if password == ADMIN_PASSWORD:
       grant_access()
   ```
   The regex requires a string literal on the RHS of the comparison. Comparing against a constant variable evades detection (though SEC-001 should catch the constant assignment).

2. **Using hash comparison with a hardcoded hash (MEDIUM likelihood)**
   ```python
   if hashlib.sha256(password.encode()).hexdigest() == "5e884898da28...":
       grant_access()
   ```
   The regex only matches `password == "string"`. A hash comparison is not detected, even though a hardcoded hash is still a hardcoded credential.

3. **Database lookup with hardcoded fallback (MEDIUM likelihood)**
   ```python
   stored = db.get_password() or "default_admin_pass"
   if password == stored:
       grant_access()
   ```
   Using `or` to set a hardcoded fallback is not detected since the comparison uses a variable.

**Hardening:** Detect hardcoded hash comparisons: `hexdigest\(\)\s*==\s*"[0-9a-f]+"`. Detect constant assignments used in auth comparisons via simple taint tracking.

---

### BATOU-AUTH-002: Missing Auth Check

**Detection mechanism:** File-level heuristic -- checks if auth middleware keywords exist anywhere in the file, then flags sensitive route handlers.

**Evasion techniques:**

1. **Auth middleware defined in a separate file (HIGH likelihood -- standard practice)**
   ```go
   // routes.go
   http.HandleFunc("/admin/dashboard", adminDashboard)
   // middleware.go has authMiddleware
   ```
   The scanner checks for auth middleware keywords in the SAME file. In any well-structured app, middleware is in a separate file, so `hasAuthMiddleware` would be false and the finding would be raised as a false positive. Conversely, if middleware is in the same file, it suppresses ALL route findings even if some routes don't use it.

2. **Non-standard middleware naming (MEDIUM likelihood)**
   ```javascript
   app.get('/admin/users', checkLogin, (req, res) => { ... });
   ```
   The middleware regex `reExpressAuthMW` matches `auth|authenticate|isAuthenticated|requireAuth|verifyToken|passport.authenticate`. `checkLogin` is NOT in this list, so it would not suppress the finding even though auth IS present. This is a false positive.

**Hardening:** This rule has inherently high false positive/negative rates due to per-file analysis. Consider making it `low` confidence across the board and documenting the limitation.

---

### BATOU-AUTH-003: CORS Wildcard

**Evasion techniques:**

1. **Dynamic origin reflection (HIGH likelihood -- common anti-pattern)**
   ```javascript
   app.use(cors({
     origin: (origin, callback) => callback(null, origin)  // Reflects any origin
   }));
   ```
   The regex only detects `origin: '*'` or `AllowAllOrigins: true`. Dynamically reflecting the `Origin` header is equally dangerous but not detected.

2. **Setting header directly with reflected value (MEDIUM likelihood)**
   ```go
   w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
   ```
   The regex looks for `*` as the value. Reflecting the request's Origin header is not detected.

**Hardening:** Detect `origin: (origin` callback patterns in CORS config. Detect `Access-Control-Allow-Origin` set to a request header value.

---

### BATOU-AUTH-006: Insecure Cookie

**Evasion techniques:**

1. **Express cookie-session middleware (MEDIUM likelihood)**
   ```javascript
   const session = require('cookie-session');
   app.use(session({ name: 'session', keys: ['secret'] }));
   ```
   The regex only detects `.cookie(` calls. Middleware-based session cookies are not checked for secure/httponly flags.

2. **Go cookie set via http.SetCookie function (MEDIUM likelihood)**
   ```go
   http.SetCookie(w, &http.Cookie{Name: "session", Value: token})
   ```
   The regex detects `http.Cookie{` struct literals, so this IS detected. But the look-ahead for Secure/HttpOnly flags within 15 lines is a rough heuristic that may miss or over-match.

**Hardening:** Add patterns for session middleware configuration (cookie-session, express-session) to check for secure/httpOnly options.

---

## 8. Generic Rules

### BATOU-GEN-002: Unsafe Deserialization

**Detection mechanism:** Matches `pickle.load`, `yaml.load` (without SafeLoader), `ObjectInputStream`, `Marshal.load`, `unserialize`, `node-serialize.unserialize`.

**Evasion techniques:**

1. **Using pickle via alternate module names (MEDIUM likelihood)**
   ```python
   import cPickle
   cPickle.loads(user_data)  # Python 2 compat
   ```
   The regex `rePickleLoads` matches `pickle.loads?\(`. `cPickle.loads` does NOT match.

   ```python
   import _pickle
   _pickle.loads(user_data)
   ```
   The internal `_pickle` module is also not matched.

2. **yaml.load with FullLoader (incorrectly suppressed)**
   ```python
   yaml.load(data, Loader=yaml.FullLoader)
   ```
   The scanner suppresses when `FullLoader` is present, but `FullLoader` is NOT safe for untrusted input -- it can still execute arbitrary Python code via `!!python/object` tags. Only `SafeLoader` is truly safe.

3. **Java custom ObjectInputStream subclass (MEDIUM likelihood)**
   ```java
   MyObjectInputStream ois = new MyObjectInputStream(input);
   Object obj = ois.readObject();
   ```
   The regex matches `ObjectInputStream(`. A custom subclass name would not match.

**Hardening:** Remove `FullLoader` from the safe-loader suppression -- only `SafeLoader` and `yaml.safe_load` should suppress. Add `cPickle`, `_pickle`, `dill`, `cloudpickle` to the pickle patterns.

---

### BATOU-GEN-004: Open Redirect

**Detection mechanism:** Matches redirect calls with request parameter arguments (e.g., `redirect(request.args`, `res.redirect(req.query`).

**Evasion techniques:**

1. **Intermediate variable (HIGH likelihood in AI code)**
   ```python
   next_url = request.args.get('next', '/')
   return redirect(next_url)
   ```
   The regex `rePyRedirect` requires `redirect\s*\(\s*request\.(?:args|GET|POST|params)`. Using an intermediate variable evades detection.

2. **Using Flask url_for with user-controlled endpoint (MEDIUM likelihood)**
   ```python
   return redirect(url_for(request.args.get('endpoint')))
   ```
   The argument to redirect is `url_for(...)`, not `request.args` directly. This evades the regex.

**Hardening:** Track variables assigned from request parameters and flag when they flow into redirect calls. This is the same taint-tracking gap seen across multiple rules.

---

### BATOU-GEN-007: Mass Assignment

**Detection mechanism:** Matches `BindJSON(&struct)`, `params.permit!`, `fields = '__all__'`, `{ ...req.body }`.

**Evasion techniques:**

1. **Go: using json.Decoder instead of gin Bind (HIGH likelihood)**
   ```go
   var user User
   json.NewDecoder(r.Body).Decode(&user)
   ```
   The regex `reGoBindJSON` matches `.ShouldBindJSON|BindJSON|ShouldBind|Bind|Decode`. Wait, `.Decode` IS in the list! So `json.NewDecoder(r.Body).Decode(&user)` WOULD match `.Decode\s*\(\s*&`. This IS detected.

2. **JavaScript: using a DTO/model create with req.body (HIGH likelihood)**
   ```javascript
   const user = await User.create(req.body);
   ```
   This is a mass assignment via ORM, not via object spread. The regex only detects `{ ...req.body }` spread syntax. Passing `req.body` directly to an ORM create method is not detected.

**Hardening:** Add patterns for ORM mass assignment: `Model.create(req.body)`, `Model.update(req.body)`, `Model.findOneAndUpdate({}, req.body)`.

---

## 9. Logging Rules

### BATOU-LOG-001: Unsanitized Log Input

**Detection mechanism:** Matches logging calls (logging.info, logger.warn, console.log, etc.) that contain request data references on the same line.

**Evasion techniques:**

1. **Logging an intermediate variable (HIGH likelihood)**
   ```python
   username = request.args.get('username')
   logger.info(f"Login attempt for {username}")
   ```
   The regex `reLogPyLogger` requires `request\.|req\.|params|query|body|user_input|form\[` on the logging line. Using an intermediate variable `username` does not match these patterns.

2. **Structured logging with request data (MEDIUM likelihood)**
   ```python
   logger.info("Login attempt", extra={"username": request.args.get('username')})
   ```
   The regex matches because `request.` appears on the logging line. But structured logging IS the recommended approach! This creates a false positive for the correct solution.

**Hardening:** Distinguish between string interpolation (dangerous) and structured logging with separate fields (safe). Suppress findings when `extra=`, key-value pairs, or structured logging patterns are used.

---

### BATOU-LOG-003: Sensitive Data in Logs

**Detection mechanism:** Matches logging calls containing words like `password`, `token`, `api_key`, `credit_card`, `ssn`, `private_key`.

**Evasion techniques:**

1. **Abbreviated or encoded field names (MEDIUM likelihood)**
   ```python
   logger.info(f"Auth result: {auth_tok}")  # 'auth_tok' doesn't match 'token'
   logger.info(f"User cred: {user_cred}")  # 'cred' doesn't match 'credential'
   ```
   The pattern requires exact words like `password|token|api_key|credit.?card|ssn|private.?key`. Abbreviated forms evade detection.

2. **Logging entire objects that contain sensitive fields (HIGH likelihood)**
   ```javascript
   console.log("User object:", user);  // user has .password field
   ```
   The regex only checks for sensitive field name strings on the logging line. Logging an entire object that contains sensitive properties is not detected.

**Hardening:** Add abbreviated forms: `cred`, `tok`, `pwd`, `auth`. Note the inherent limitation for object-level logging.

---

## 10. Validation Rules

### BATOU-VAL-001: Direct Parameter Usage

**Detection mechanism:** Matches request parameter access patterns (req.params, request.args, $_GET, etc.) and suppresses if validation/sanitization keywords appear within 10 lines.

**Evasion techniques:**

1. **Validation function with non-standard name (HIGH likelihood)**
   ```javascript
   function checkInput(val) { return val.trim(); }
   const name = checkInput(req.body.name);
   ```
   The validation suppression regex `reValidationPresent` looks for specific keywords: `validate|sanitize|clean|escape|parseInt|...`. A custom function named `checkInput` or `processInput` does not match, causing a false positive.

2. **Accessing nested request properties (MEDIUM likelihood)**
   ```javascript
   const data = req.body;
   const name = data.name;  // No longer matches 'req.body'
   ```
   The regex `reExpressParams` matches `req.(?:params|query|body)`. Assigning `req.body` to a variable and then accessing properties evades detection.

3. **TypeScript/Express with typed request (MEDIUM likelihood)**
   ```typescript
   const { name, email } = req.body as UserInput;  // Destructuring
   ```
   The regex matches `req.body` on this line. Destructuring IS a form of field restriction, but the scanner flags it anyway. This is a false positive for the safe pattern.

**Hardening:** Add common custom validation function names to the suppression list. Detect destructuring as a form of field restriction.

---

## 11. Memory Rules

### BATOU-MEM-001: Banned Functions

**Detection mechanism:** Matches `gets(`, `strcpy(`, `strcat(`, `sprintf(`, `vsprintf(`, `scanf` with `%s`, `atoi(`.

**Evasion techniques:**

1. **Macro wrappers (MEDIUM likelihood)**
   ```c
   #define COPY(dst, src) strcpy(dst, src)
   COPY(buffer, user_input);
   ```
   The macro expansion `COPY(buffer, user_input)` does not match `strcpy(`. The actual `strcpy` is hidden inside the macro definition which could be in a header file.

2. **Using _s (safe) variants that are still misused (MEDIUM likelihood)**
   ```c
   strcpy_s(dst, sizeof(dst), src);  // Not detected
   ```
   The regex matches `strcpy(` but not `strcpy_s(` since the `\b` word boundary and `strcpy\s*\(` pattern would not match `strcpy_s`. This is correct behavior -- `_s` variants are safe. But the scanner doesn't verify correct usage of the `_s` variants.

3. **Function pointers (LOW likelihood)**
   ```c
   void *(*copier)(void*, const void*, size_t) = memcpy;
   copier(dst, src, len);
   ```
   Using function pointers to banned functions evades detection.

**Hardening:** This is an inherent limitation of regex-based analysis for C/C++. Consider noting that macro-level and function-pointer evasion require a proper C preprocessor and AST-based analysis.

---

### BATOU-MEM-004: Memory Management (Use After Free / Double Free)

**Detection mechanism:** Tracks `free(ptr)` calls and checks for subsequent use of the same pointer name, resetting on `}` braces.

**Evasion techniques:**

1. **Pointer aliasing (HIGH likelihood)**
   ```c
   char *a = malloc(100);
   char *b = a;
   free(a);
   strcpy(b, "hello");  // Use after free via alias, not detected
   ```
   The tracker only stores the exact variable name passed to `free()`. Aliases are not tracked.

2. **Free in conditional branch (HIGH likelihood)**
   ```c
   if (error) {
       free(ptr);
   }
   // Reset on '}' clears the tracking
   ptr->field = 0;  // Use after conditional free, not detected
   ```
   The tracker resets `freedVars` on every `}` line, so free inside a conditional block doesn't persist after the closing brace.

3. **Free via wrapper function (MEDIUM likelihood)**
   ```c
   void cleanup(char *p) { free(p); p = NULL; }
   cleanup(buffer);
   buffer->data;  // Use after free via wrapper
   ```
   The regex only matches literal `free(` calls. Wrapper functions that call free are not tracked.

**Hardening:** Don't reset on `}` that are clearly inside if/else blocks (only reset on function-level `}`). Track pointer aliases through simple assignment chains. These improvements are limited without full AST analysis.

---

## 12. Cross-Cutting Evasion Techniques

These techniques work against multiple rule categories simultaneously:

### A. Line-Splitting

**Affects:** ALL rules (INJ, XSS, TRV, SSRF, etc.)

Every rule in Batou operates on individual lines. Any vulnerability can be made undetectable by splitting the dangerous operation across multiple lines:

```javascript
// Detected:
db.query("SELECT * FROM users WHERE id = " + userId);

// Not detected:
const q = "SELECT * FROM users WHERE id = ";
db.query(q + userId);
```

**AI likelihood:** HIGH. AI models frequently produce multi-line code for readability.

**Hardening:** Implement a line-joining preprocessor that concatenates string assignments with their usage sites, at least for the most critical rules (SQL injection, command injection).

### B. Intermediate Variable Assignment

**Affects:** ALL rules

```python
# Detected:
cursor.execute(f"SELECT * FROM users WHERE id = {request.args.get('id')}")

# Not detected:
uid = request.args.get('id')
cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
```

**AI likelihood:** VERY HIGH. This is standard code practice.

**Hardening:** Implement simple intra-function taint tracking: if a variable is assigned from a user-input source (request.*, req.*, etc.), mark that variable as tainted and flag it when used in sinks (SQL queries, exec calls, file operations, etc.).

### C. Helper Function Wrapping

**Affects:** ALL rules

```python
def safe_query(query):
    """This is NOT actually safe."""
    return db.execute(query)

safe_query(f"SELECT * FROM users WHERE id = {uid}")
```

**AI likelihood:** MEDIUM. AI code often creates utility functions.

**Hardening:** Inter-procedural analysis is expensive for regex-based tools. A pragmatic approach: flag helper functions that contain dangerous sinks (exec, query, eval) and warn when they're called with formatted/concatenated strings.

### D. Comment-Line Evasion

**Affects:** Rules that skip comment lines

All rules skip lines starting with `//`, `#`, `/*`, `*`, `--`. Multi-line comments are only detected by their first line:

```python
"""
This docstring contains code that won't be scanned:
eval(user_input)
"""
# But the eval above is inside a string, not executable code. No real evasion here.
```

This is NOT a practical evasion since code inside comments/strings isn't executed. The comment skipping is appropriate.

### E. Encoding/Obfuscation

**Affects:** Secrets, crypto, injection rules

```python
import base64
password = base64.b64decode("cGFzc3dvcmQxMjM=").decode()  # "password123"
```

**AI likelihood:** LOW for intentional evasion, MEDIUM for legitimate encoding patterns.

**Hardening:** Detect `base64.b64decode`, `Buffer.from(..., 'base64')`, `atob()` near variable assignments to sensitive-named variables.

---

## 13. Summary and Risk Matrix

### Evasion Risk by Category

| Category | Evasion Risk | Most Critical Gap | AI Likelihood |
|----------|-------------|-------------------|---------------|
| Injection (INJ) | **HIGH** | Multi-line query construction; intermediate variables | VERY HIGH |
| XSS | **HIGH** | insertAdjacentHTML, jQuery .html(); intermediate variables in reflected XSS | HIGH |
| Traversal (TRV) | **MEDIUM** | Python tarfile.extract() not detected; intermediate variables | HIGH |
| Crypto (CRY) | **MEDIUM** | Third-party hash libraries; variable algorithm names; yaml FullLoader not safe | MEDIUM |
| Secrets (SEC) | **MEDIUM** | Non-standard variable names; newer API key formats (OpenAI, Anthropic) | HIGH |
| SSRF | **HIGH** | Non-standard IP encodings; DNS-based SSRF; wrapper functions | HIGH |
| Auth (AUTH) | **HIGH** | Cross-file middleware; reflected CORS origin; variable credential comparison | VERY HIGH |
| Generic (GEN) | **HIGH** | Open redirect via intermediate variable; ORM mass assignment | HIGH |
| Logging (LOG) | **MEDIUM** | Intermediate variables; object-level logging | HIGH |
| Validation (VAL) | **MEDIUM** | Custom validation function names; destructured req.body | HIGH |
| Memory (MEM) | **MEDIUM** | Pointer aliasing; macro wrappers; conditional free | MEDIUM |

### Top 5 Highest-Impact Fixes

1. **Implement basic intra-function taint tracking** -- Would close the #1 evasion vector across ALL categories. Track variables assigned from request/user-input sources and flag when they flow into dangerous sinks. Even a simple 10-line-window taint track would dramatically reduce evasion.

2. **Fix yaml.load FullLoader suppression (GEN-002)** -- FullLoader is NOT safe for untrusted input. Removing it from the safe-loader list is a one-line fix that closes a real vulnerability gap.

3. **Add NoSQL injection patterns for direct req.body pass-through (INJ-007)** -- The most common NoSQL injection pattern (`db.find(req.body)`) is completely undetected.

4. **Add insertAdjacentHTML and jQuery .html() patterns (XSS-001)** -- These are extremely common in AI-generated JavaScript and are functionally identical to innerHTML.

5. **Add non-standard IP encoding patterns for SSRF (SSRF-002)** -- Decimal, hex, octal, and IPv6-mapped IPv4 addresses are well-known SSRF bypass techniques.

### Assessment for Blog Post

The regex-based approach provides excellent **breadth** of coverage (55+ rules across 11 categories, 8+ programming languages) and catches the most obvious patterns that AI code generators frequently produce. However, it has a fundamental **depth** limitation: per-line analysis without taint tracking means that any code written across multiple lines or using intermediate variables can evade detection.

For the blog post, this represents an honest trade-off: Batou is designed as a fast, lightweight first line of defense in a Claude Code hook, not as a replacement for a full SAST tool. The evasion techniques documented here would require significantly more complex analysis (AST parsing, data flow tracking, inter-procedural analysis) that would impact the sub-second performance requirement.

The recommended framing: "Batou catches the common patterns that AI models produce. For production security, complement it with a full SAST pipeline."
