#!/usr/bin/env python3
"""Generate Go OWASP-style benchmark test fixtures.

Creates 180 Go files (9 categories × 20 cases each: 10 vulnerable + 10 safe)
and an expectedresults.csv ground truth file.
"""

import os
import csv

BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "testdata", "bench", "go")

# Category definitions: (category, CWE, vulnerable_templates, safe_templates)
# Each template list has 10 entries. Templates are (description, body) tuples.
# body uses {pkg} for extra imports, {handler_name} for the function name.

CATEGORIES = []

# ============================================================
# SQL Injection (CWE-89)
# ============================================================
SQLI_VULN = [
    ("SQL injection via string concatenation",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	param := r.URL.Query().Get("id")
	query := "SELECT * FROM users WHERE id = " + param
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query(query)
}}'''),
    ("SQL injection via fmt.Sprintf",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	param := r.FormValue("name")
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", param)
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Exec(query)
}}'''),
    ("SQL injection via QueryRow with concat",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	param := r.URL.Query().Get("email")
	db, _ := sql.Open("sqlite3", ":memory:")
	db.QueryRow("SELECT id FROM users WHERE email = '" + param + "'")
}}'''),
    ("SQL injection via channel propagation",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	param := r.FormValue("search")
	ch := make(chan string, 1)
	ch <- param
	tainted := <-ch
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT * FROM items WHERE name = '" + tainted + "'")
}}'''),
    ("SQL injection via goroutine",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	param := r.URL.Query().Get("sort")
	db, _ := sql.Open("sqlite3", ":memory:")
	go func() {{
		query := "SELECT * FROM items ORDER BY " + param
		db.Query(query)
	}}()
}}'''),
    ("SQL injection via defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	param := r.PostFormValue("table")
	db, _ := sql.Open("sqlite3", ":memory:")
	query := "DROP TABLE " + param
	defer db.Exec(query)
}}'''),
    ("SQL injection via Header.Get",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	tenant := r.Header.Get("X-Tenant-ID")
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT * FROM data WHERE tenant = '" + tenant + "'")
}}'''),
    ("SQL injection via multiple assignments",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("filter")
	filter := raw
	clause := "WHERE status = '" + filter + "'"
	query := "SELECT * FROM orders " + clause
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query(query)
}}'''),
    ("SQL injection via string builder pattern",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	col := r.FormValue("column")
	val := r.FormValue("value")
	query := "SELECT * FROM products WHERE " + col + " = '" + val + "'"
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Exec(query)
}}'''),
    ("SQL injection via Cookie",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	cookie, _ := r.Cookie("session_data")
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT * FROM sessions WHERE data = '" + cookie.Value + "'")
}}'''),
]

SQLI_SAFE = [
    ("Parameterized query",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	param := r.URL.Query().Get("id")
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT * FROM users WHERE id = ?", param)
}}'''),
    ("Parameterized Exec",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	param := r.FormValue("name")
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Exec("INSERT INTO users (name) VALUES (?)", param)
}}'''),
    ("Parameterized QueryRow",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	param := r.URL.Query().Get("email")
	db, _ := sql.Open("sqlite3", ":memory:")
	db.QueryRow("SELECT id FROM users WHERE email = ?", param)
}}'''),
    ("Prepared statement",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	param := r.FormValue("search")
	db, _ := sql.Open("sqlite3", ":memory:")
	stmt, _ := db.Prepare("SELECT * FROM items WHERE name = ?")
	stmt.Query(param)
}}'''),
    ("Integer conversion sanitizer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("id")
	id, err := strconv.Atoi(raw)
	if err != nil {{
		http.Error(w, "bad id", 400)
		return
	}}
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT * FROM users WHERE id = ?", id)
}}'''),
    ("Hardcoded query, no user input",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT * FROM users WHERE active = true")
}}'''),
    ("Parameterized with channel",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	param := r.FormValue("id")
	ch := make(chan string, 1)
	ch <- param
	val := <-ch
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT * FROM users WHERE id = ?", val)
}}'''),
    ("Parameterized in goroutine",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	param := r.URL.Query().Get("name")
	db, _ := sql.Open("sqlite3", ":memory:")
	go func() {{
		db.Exec("INSERT INTO log (name) VALUES (?)", param)
	}}()
}}'''),
    ("Parameterized with defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	param := r.PostFormValue("id")
	db, _ := sql.Open("sqlite3", ":memory:")
	stmt, _ := db.Prepare("DELETE FROM temp WHERE id = ?")
	defer stmt.Exec(param)
}}'''),
    ("Query with integer format only",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("limit")
	limit, _ := strconv.Atoi(raw)
	db, _ := sql.Open("sqlite3", ":memory:")
	query := fmt.Sprintf("SELECT * FROM items LIMIT %d", limit)
	db.Query(query)
}}'''),
]

CATEGORIES.append(("sqli", "89", SQLI_VULN, SQLI_SAFE))

# ============================================================
# Command Injection (CWE-78)
# ============================================================
CMDI_VULN = [
    ("Command injection via exec.Command",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	cmd := r.URL.Query().Get("cmd")
	exec.Command("sh", "-c", cmd).Run()
}}'''),
    ("Command injection via variable assignment",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	filename := r.FormValue("file")
	c := exec.Command("cat", filename)
	c.Run()
}}'''),
    ("Command injection via channel",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	input := r.URL.Query().Get("host")
	ch := make(chan string, 1)
	ch <- input
	host := <-ch
	exec.Command("ping", host).Run()
}}'''),
    ("Command injection via goroutine",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.FormValue("target")
	go func() {{
		exec.Command("nslookup", target).Run()
	}}()
}}'''),
    ("Command injection via Header",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	userAgent := r.Header.Get("User-Agent")
	exec.Command("echo", userAgent).Output()
}}'''),
    ("Command injection via string concat in shell",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	dir := r.URL.Query().Get("dir")
	exec.Command("sh", "-c", "ls -la "+dir).Run()
}}'''),
    ("Command injection via defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	path := r.FormValue("path")
	defer exec.Command("rm", path).Run()
}}'''),
    ("Command injection via PostFormValue",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	script := r.PostFormValue("script")
	exec.Command("bash", "-c", script).CombinedOutput()
}}'''),
    ("Command injection via Cookie",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	cookie, _ := r.Cookie("tool")
	exec.Command(cookie.Value).Run()
}}'''),
    ("Command injection via multiple hops",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("prog")
	prog := raw
	arg := "--version"
	exec.Command(prog, arg).Run()
}}'''),
]

CMDI_SAFE = [
    ("Fixed command with no user args",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	exec.Command("ls", "-la", "/tmp").Run()
}}'''),
    ("Command with validated allowlist",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	tool := r.URL.Query().Get("tool")
	allowed := map[string]bool{{"date": true, "uptime": true, "whoami": true}}
	if !allowed[tool] {{
		http.Error(w, "not allowed", 400)
		return
	}}
	exec.Command(tool).Run()
}}'''),
    ("Fixed command, user input only in stdin",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	data := r.FormValue("data")
	c := exec.Command("wc", "-l")
	c.Stdin = strings.NewReader(data)
	c.Run()
}}'''),
    ("Integer arg only",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("count")
	count, err := strconv.Atoi(raw)
	if err != nil {{
		http.Error(w, "bad count", 400)
		return
	}}
	exec.Command("seq", strconv.Itoa(count)).Run()
}}'''),
    ("Hardcoded args, goroutine",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	go func() {{
		exec.Command("date", "+%Y-%m-%d").Run()
	}}()
}}'''),
    ("Hardcoded command via channel",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	ch := make(chan string, 1)
	ch <- "hostname"
	cmd := <-ch
	_ = cmd
	exec.Command("hostname").Run()
}}'''),
    ("Fixed command with defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	defer exec.Command("sync").Run()
}}'''),
    ("Regex-validated input",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.FormValue("name")
	matched, _ := regexp.MatchString("^[a-zA-Z0-9]+$", name)
	if !matched {{
		http.Error(w, "invalid", 400)
		return
	}}
	exec.Command("echo", name).Run()
}}'''),
    ("Hardcoded echo",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	_ = r.URL.Query().Get("ignored")
	exec.Command("echo", "hello world").Run()
}}'''),
    ("Fixed binary, user data via pipe not arg",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	input := r.FormValue("text")
	c := exec.Command("grep", "pattern")
	c.Stdin = strings.NewReader(input)
	c.Run()
}}'''),
]

CATEGORIES.append(("cmdi", "78", CMDI_VULN, CMDI_SAFE))

# ============================================================
# Path Traversal (CWE-22)
# ============================================================
PATHTRAVER_VULN = [
    ("Path traversal via os.Open",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	filename := r.URL.Query().Get("file")
	f, _ := os.Open(filename)
	defer f.Close()
	io.Copy(w, f)
}}'''),
    ("Path traversal via os.ReadFile",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	path := r.FormValue("path")
	data, _ := os.ReadFile(path)
	w.Write(data)
}}'''),
    ("Path traversal via filepath.Join unsanitized",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.URL.Query().Get("name")
	full := filepath.Join("/data/uploads", name)
	f, _ := os.Open(full)
	defer f.Close()
	io.Copy(w, f)
}}'''),
    ("Path traversal via os.Create",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	dest := r.FormValue("dest")
	f, _ := os.Create(dest)
	defer f.Close()
	io.Copy(f, r.Body)
}}'''),
    ("Path traversal via channel",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.URL.Query().Get("doc")
	ch := make(chan string, 1)
	ch <- name
	doc := <-ch
	data, _ := os.ReadFile("/docs/" + doc)
	w.Write(data)
}}'''),
    ("Path traversal via goroutine file write",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	dest := r.FormValue("output")
	body, _ := io.ReadAll(r.Body)
	go func() {{
		os.WriteFile(dest, body, 0644)
	}}()
}}'''),
    ("Path traversal via os.Remove",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	file := r.URL.Query().Get("delete")
	os.Remove(file)
}}'''),
    ("Path traversal via Header",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	path := r.Header.Get("X-File-Path")
	data, _ := os.ReadFile(path)
	w.Write(data)
}}'''),
    ("Path traversal via defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	tmp := r.FormValue("tmp")
	defer os.Remove(tmp)
	data, _ := os.ReadFile(tmp)
	w.Write(data)
}}'''),
    ("Path traversal via Cookie value",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	cookie, _ := r.Cookie("download")
	f, _ := os.Open(cookie.Value)
	defer f.Close()
	io.Copy(w, f)
}}'''),
]

PATHTRAVER_SAFE = [
    ("filepath.Base sanitizer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.URL.Query().Get("file")
	safe := filepath.Base(name)
	f, _ := os.Open(filepath.Join("/uploads", safe))
	defer f.Close()
	io.Copy(w, f)
}}'''),
    ("filepath.Clean + HasPrefix check",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.FormValue("path")
	cleaned := filepath.Clean(filepath.Join("/data", name))
	if !strings.HasPrefix(cleaned, "/data/") {{
		http.Error(w, "forbidden", 403)
		return
	}}
	data, _ := os.ReadFile(cleaned)
	w.Write(data)
}}'''),
    ("Hardcoded path, no user input",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	data, _ := os.ReadFile("/etc/config.json")
	w.Write(data)
}}'''),
    ("Integer-based file lookup",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("id")
	id, err := strconv.Atoi(raw)
	if err != nil {{
		http.Error(w, "bad id", 400)
		return
	}}
	path := fmt.Sprintf("/data/files/%d.dat", id)
	data, _ := os.ReadFile(path)
	w.Write(data)
}}'''),
    ("Embed FS, no real file access",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	_ = r.URL.Query().Get("file")
	w.Write([]byte("static content only"))
}}'''),
    ("filepath.Base in goroutine",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.FormValue("file")
	safe := filepath.Base(name)
	go func() {{
		data, _ := os.ReadFile(filepath.Join("/safe", safe))
		_ = data
	}}()
}}'''),
    ("Allowlist of filenames",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.URL.Query().Get("doc")
	allowed := map[string]bool{{"readme.txt": true, "license.txt": true}}
	if !allowed[name] {{
		http.Error(w, "not found", 404)
		return
	}}
	data, _ := os.ReadFile(filepath.Join("/docs", name))
	w.Write(data)
}}'''),
    ("filepath.Base via channel",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.URL.Query().Get("f")
	ch := make(chan string, 1)
	ch <- filepath.Base(name)
	safe := <-ch
	data, _ := os.ReadFile(filepath.Join("/uploads", safe))
	w.Write(data)
}}'''),
    ("Hardcoded remove with defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	_ = r.FormValue("ignored")
	defer os.Remove("/tmp/cleanup.tmp")
}}'''),
    ("filepath.Abs validation",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.URL.Query().Get("file")
	abs, _ := filepath.Abs(filepath.Join("/safe", name))
	if !strings.HasPrefix(abs, "/safe/") {{
		http.Error(w, "forbidden", 403)
		return
	}}
	data, _ := os.ReadFile(abs)
	w.Write(data)
}}'''),
]

CATEGORIES.append(("pathtraver", "22", PATHTRAVER_VULN, PATHTRAVER_SAFE))

# ============================================================
# SSRF (CWE-918)
# ============================================================
SSRF_VULN = [
    ("SSRF via http.Get",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.URL.Query().Get("url")
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
    ("SSRF via http.Post",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.FormValue("endpoint")
	resp, _ := http.Post(target, "application/json", r.Body)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
    ("SSRF via http.NewRequest",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.URL.Query().Get("api")
	req, _ := http.NewRequest("GET", target, nil)
	client := &http.Client{{}}
	resp, _ := client.Do(req)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
    ("SSRF via channel propagation",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	rawURL := r.FormValue("fetch")
	ch := make(chan string, 1)
	ch <- rawURL
	target := <-ch
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
    ("SSRF via goroutine",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.URL.Query().Get("webhook")
	go func() {{
		http.Get(target)
	}}()
	w.WriteHeader(202)
}}'''),
    ("SSRF via Header value",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	callback := r.Header.Get("X-Callback-URL")
	resp, _ := http.Get(callback)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
    ("SSRF via string concat URL",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	host := r.URL.Query().Get("host")
	target := "http://" + host + "/api/data"
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
    ("SSRF via defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.FormValue("notify")
	defer http.Get(target)
	w.WriteHeader(200)
}}'''),
    ("SSRF via PostFormValue",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.PostFormValue("redirect_url")
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
    ("SSRF via Cookie",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	cookie, _ := r.Cookie("api_endpoint")
	resp, _ := http.Get(cookie.Value)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
]

SSRF_SAFE = [
    ("Hardcoded URL",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	resp, _ := http.Get("https://api.example.com/data")
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
    ("URL parse + host allowlist",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.URL.Query().Get("url")
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host != "api.trusted.com" {{
		http.Error(w, "forbidden", 403)
		return
	}}
	resp, _ := http.Get(parsed.String())
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
    ("Path-only user input, fixed host",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	path := r.URL.Query().Get("path")
	target := "https://internal.api.com/" + url.PathEscape(path)
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
    ("Allowlist map check",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	svc := r.FormValue("service")
	endpoints := map[string]string{{"users": "http://users-svc:8080", "orders": "http://orders-svc:8080"}}
	target, ok := endpoints[svc]
	if !ok {{
		http.Error(w, "unknown service", 400)
		return
	}}
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
    ("Hardcoded in goroutine",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	go func() {{
		http.Get("https://hooks.example.com/notify")
	}}()
	w.WriteHeader(202)
}}'''),
    ("IP parse validation",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	host := r.URL.Query().Get("host")
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() {{
		http.Error(w, "forbidden", 403)
		return
	}}
	resp, _ := http.Get("http://" + ip.String() + ":8080/api")
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
    ("Fixed URL via channel",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	ch := make(chan string, 1)
	ch <- "https://safe.example.com/data"
	target := <-ch
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
    ("Hardcoded with defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	defer http.Get("https://metrics.internal/ping")
	w.WriteHeader(200)
}}'''),
    ("URL parse sanitizer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.FormValue("url")
	parsed, err := url.Parse(raw)
	if err != nil {{
		http.Error(w, "bad url", 400)
		return
	}}
	allowed := map[string]bool{{"api.example.com": true}}
	if !allowed[parsed.Host] {{
		http.Error(w, "forbidden", 403)
		return
	}}
	resp, _ := http.Get(parsed.String())
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
    ("Integer-based endpoint selection",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("svc")
	idx, _ := strconv.Atoi(raw)
	endpoints := []string{{"https://svc1.internal", "https://svc2.internal"}}
	if idx < 0 || idx >= len(endpoints) {{
		http.Error(w, "bad index", 400)
		return
	}}
	resp, _ := http.Get(endpoints[idx])
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}}'''),
]

CATEGORIES.append(("ssrf", "918", SSRF_VULN, SSRF_SAFE))

# ============================================================
# SSTI / Template Injection (CWE-1336)
# ============================================================
SSTI_VULN = [
    ("Template injection via text/template Parse",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	tmplStr := r.FormValue("template")
	t, _ := template.New("t").Parse(tmplStr)
	t.Execute(w, nil)
}}'''),
    ("Template injection via fmt.Sprintf template",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.URL.Query().Get("name")
	tmplStr := fmt.Sprintf("Hello {{{{.Name}}}}! %s", name)
	t, _ := template.New("t").Parse(tmplStr)
	t.Execute(w, map[string]string{{"Name": "World"}})
}}'''),
    ("Template injection via channel",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	input := r.FormValue("tpl")
	ch := make(chan string, 1)
	ch <- input
	tmplStr := <-ch
	t, _ := template.New("t").Parse(tmplStr)
	t.Execute(w, nil)
}}'''),
    ("Template injection via goroutine",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	tmplStr := r.URL.Query().Get("layout")
	go func() {{
		t, _ := template.New("t").Parse(tmplStr)
		t.Execute(w, nil)
	}}()
}}'''),
    ("Template injection via Header",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	tmplStr := r.Header.Get("X-Template")
	t, _ := template.New("t").Parse(tmplStr)
	t.Execute(w, nil)
}}'''),
    ("Template injection via concatenation",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	header := r.FormValue("header")
	tmplStr := "<h1>" + header + "</h1>{{{{.Body}}}}"
	t, _ := template.New("t").Parse(tmplStr)
	t.Execute(w, map[string]string{{"Body": "content"}})
}}'''),
    ("Template injection via PostFormValue",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	body := r.PostFormValue("body")
	t, _ := template.New("t").Parse(body)
	t.Execute(w, nil)
}}'''),
    ("Template injection via defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	tmplStr := r.FormValue("footer")
	t, _ := template.New("t").Parse(tmplStr)
	defer t.Execute(w, nil)
}}'''),
    ("Template injection via multiple vars",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("tmpl")
	userTmpl := raw
	t, _ := template.New("t").Parse(userTmpl)
	t.Execute(w, nil)
}}'''),
    ("Template injection via Cookie",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	cookie, _ := r.Cookie("theme_template")
	t, _ := template.New("t").Parse(cookie.Value)
	t.Execute(w, nil)
}}'''),
]

SSTI_SAFE = [
    ("Fixed template, user data in context only",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.FormValue("name")
	t, _ := template.New("t").Parse("Hello, {{{{.Name}}}}!")
	t.Execute(w, map[string]string{{"Name": name}})
}}'''),
    ("Precompiled template",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.URL.Query().Get("name")
	tmpl := template.Must(template.New("t").Parse("<p>Welcome {{{{.}}}}</p>"))
	tmpl.Execute(w, name)
}}'''),
    ("html/template auto-escaping",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.FormValue("name")
	t, _ := htmltemplate.New("t").Parse("<p>Hello {{{{.}}}}</p>")
	t.Execute(w, name)
}}'''),
    ("Template from file, data from user",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.URL.Query().Get("name")
	t, _ := template.ParseFiles("templates/page.html")
	t.Execute(w, map[string]string{{"Name": name}})
}}'''),
    ("Fixed template via channel data",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.FormValue("name")
	ch := make(chan string, 1)
	ch <- name
	val := <-ch
	t, _ := template.New("t").Parse("Hello {{{{.}}}}")
	t.Execute(w, val)
}}'''),
    ("Fixed template in goroutine",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.URL.Query().Get("name")
	go func() {{
		t, _ := template.New("t").Parse("Name: {{{{.}}}}")
		t.Execute(w, name)
	}}()
}}'''),
    ("No template at all, plain write",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.FormValue("name")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{{"name": name}})
}}'''),
    ("Fixed template with defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.FormValue("name")
	t, _ := template.New("t").Parse("Goodbye {{{{.}}}}")
	defer t.Execute(w, name)
}}'''),
    ("Hardcoded template, no user input in parse",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	_ = r.URL.Query().Get("ignored")
	t, _ := template.New("t").Parse("Static page content")
	t.Execute(w, nil)
}}'''),
    ("Template from embedded string",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	msg := r.FormValue("msg")
	const tmpl = "Message: {{{{.}}}}"
	t, _ := template.New("t").Parse(tmpl)
	t.Execute(w, msg)
}}'''),
]

CATEGORIES.append(("ssti", "1336", SSTI_VULN, SSTI_SAFE))

# ============================================================
# XSS (CWE-79)
# ============================================================
XSS_VULN = [
    ("XSS via fmt.Fprintf",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}}'''),
    ("XSS via w.Write",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	msg := r.FormValue("msg")
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<div>" + msg + "</div>"))
}}'''),
    ("XSS via template.HTML bypass",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	content := r.FormValue("content")
	t, _ := htmltemplate.New("t").Parse("{{{{.}}}}")
	t.Execute(w, htmltemplate.HTML(content))
}}'''),
    ("XSS via channel propagation",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	input := r.URL.Query().Get("q")
	ch := make(chan string, 1)
	ch <- input
	val := <-ch
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<p>Search: %s</p>", val)
}}'''),
    ("XSS via goroutine write",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	msg := r.FormValue("msg")
	w.Header().Set("Content-Type", "text/html")
	go func() {{
		fmt.Fprintf(w, "<span>%s</span>", msg)
	}}()
}}'''),
    ("XSS via Header reflection",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	ua := r.Header.Get("User-Agent")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<p>Your browser: %s</p>", ua)
}}'''),
    ("XSS via fmt.Fprint",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	title := r.URL.Query().Get("title")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<title>"+title+"</title>")
}}'''),
    ("XSS via defer write",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	footer := r.FormValue("footer")
	w.Header().Set("Content-Type", "text/html")
	defer fmt.Fprintf(w, "<footer>%s</footer>", footer)
}}'''),
    ("XSS via PostFormValue",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	comment := r.PostFormValue("comment")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<div class='comment'>%s</div>", comment)
}}'''),
    ("XSS via Cookie reflection",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	cookie, _ := r.Cookie("prefs")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<script>var prefs='%s'</script>", cookie.Value)
}}'''),
]

XSS_SAFE = [
    ("html.EscapeString sanitizer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.URL.Query().Get("name")
	safe := html.EscapeString(name)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", safe)
}}'''),
    ("html/template auto-escaping",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.FormValue("name")
	t, _ := htmltemplate.New("t").Parse("<h1>Hello {{{{.}}}}</h1>")
	t.Execute(w, name)
}}'''),
    ("JSON response, no HTML",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{{"name": name}})
}}'''),
    ("Plaintext content type",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	msg := r.FormValue("msg")
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, msg)
}}'''),
    ("html.EscapeString via channel",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	input := r.URL.Query().Get("q")
	ch := make(chan string, 1)
	ch <- html.EscapeString(input)
	safe := <-ch
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<p>%s</p>", safe)
}}'''),
    ("html/template in goroutine",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	name := r.FormValue("name")
	go func() {{
		t, _ := htmltemplate.New("t").Parse("<p>{{{{.}}}}</p>")
		t.Execute(w, name)
	}}()
}}'''),
    ("Hardcoded HTML, no user input",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<h1>Welcome</h1>")
}}'''),
    ("Integer-only output",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("count")
	count, _ := strconv.Atoi(raw)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<p>Count: %d</p>", count)
}}'''),
    ("html.EscapeString with defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	msg := r.FormValue("msg")
	safe := html.EscapeString(msg)
	w.Header().Set("Content-Type", "text/html")
	defer fmt.Fprintf(w, "<footer>%s</footer>", safe)
}}'''),
    ("url.QueryEscape for attribute",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	q := r.URL.Query().Get("q")
	safe := url.QueryEscape(q)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<a href='/search?q=%s'>Search</a>", safe)
}}'''),
]

CATEGORIES.append(("xss", "79", XSS_VULN, XSS_SAFE))

# ============================================================
# Deserialization (CWE-502)
# ============================================================
DESER_VULN = [
    ("Unsafe JSON unmarshal to interface{}",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	body, _ := io.ReadAll(r.Body)
	var data interface{{}}
	json.Unmarshal(body, &data)
	fmt.Fprintf(w, "got: %v", data)
}}'''),
    ("Unsafe gob decode from request",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	var data interface{{}}
	gob.NewDecoder(r.Body).Decode(&data)
	fmt.Fprintf(w, "got: %v", data)
}}'''),
    ("Unsafe XML decode from request",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	var data interface{{}}
	xml.NewDecoder(r.Body).Decode(&data)
	fmt.Fprintf(w, "got: %v", data)
}}'''),
    ("Unsafe JSON decode via channel",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	body, _ := io.ReadAll(r.Body)
	ch := make(chan []byte, 1)
	ch <- body
	raw := <-ch
	var data interface{{}}
	json.Unmarshal(raw, &data)
	fmt.Fprintf(w, "got: %v", data)
}}'''),
    ("Unsafe gob decode in goroutine",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	go func() {{
		var data interface{{}}
		gob.NewDecoder(r.Body).Decode(&data)
	}}()
}}'''),
    ("Unsafe JSON decode via Header body",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.Header.Get("X-Payload")
	var data interface{{}}
	json.Unmarshal([]byte(raw), &data)
	fmt.Fprintf(w, "got: %v", data)
}}'''),
    ("Unsafe YAML-like decode from query",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("config")
	var data interface{{}}
	json.Unmarshal([]byte(raw), &data)
	fmt.Fprintf(w, "got: %v", data)
}}'''),
    ("Unsafe JSON decode with defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	body, _ := io.ReadAll(r.Body)
	var data interface{{}}
	defer func() {{
		json.Unmarshal(body, &data)
	}}()
}}'''),
    ("Unsafe gob from PostFormValue",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.PostFormValue("payload")
	var data interface{{}}
	gob.NewDecoder(strings.NewReader(raw)).Decode(&data)
	fmt.Fprintf(w, "got: %v", data)
}}'''),
    ("Unsafe JSON from Cookie",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	cookie, _ := r.Cookie("state")
	var data interface{{}}
	json.Unmarshal([]byte(cookie.Value), &data)
	fmt.Fprintf(w, "got: %v", data)
}}'''),
]

DESER_SAFE = [
    ("Typed struct unmarshal",
     '''type safeUser{num} struct {{
	Name  string `json:"name"`
	Email string `json:"email"`
}}

func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	var user safeUser{num}
	json.NewDecoder(r.Body).Decode(&user)
	fmt.Fprintf(w, "name: %s", user.Name)
}}'''),
    ("Typed struct with validation",
     '''type safeReq{num} struct {{
	ID   int    `json:"id"`
	Name string `json:"name"`
}}

func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	var req safeReq{num}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {{
		http.Error(w, "bad json", 400)
		return
	}}
	if req.ID <= 0 {{
		http.Error(w, "bad id", 400)
		return
	}}
	fmt.Fprintf(w, "id: %d", req.ID)
}}'''),
    ("Typed XML decode",
     '''type safeXML{num} struct {{
	XMLName xml.Name `xml:"item"`
	Value   string   `xml:"value"`
}}

func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	var item safeXML{num}
	xml.NewDecoder(r.Body).Decode(&item)
	fmt.Fprintf(w, "value: %s", item.Value)
}}'''),
    ("Hardcoded JSON, no user input",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := []byte(`{{"status":"ok"}}`)
	var data map[string]string
	json.Unmarshal(raw, &data)
	fmt.Fprintf(w, "status: %s", data["status"])
}}'''),
    ("Typed struct via channel",
     '''type safeCh{num} struct {{
	Msg string `json:"msg"`
}}

func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	body, _ := io.ReadAll(r.Body)
	ch := make(chan []byte, 1)
	ch <- body
	raw := <-ch
	var msg safeCh{num}
	json.Unmarshal(raw, &msg)
	fmt.Fprintf(w, "msg: %s", msg.Msg)
}}'''),
    ("Typed struct in goroutine",
     '''type safeGo{num} struct {{
	Action string `json:"action"`
}}

func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	body, _ := io.ReadAll(r.Body)
	go func() {{
		var act safeGo{num}
		json.Unmarshal(body, &act)
	}}()
}}'''),
    ("Map[string]string typed decode",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	var data map[string]string
	json.NewDecoder(r.Body).Decode(&data)
	fmt.Fprintf(w, "got: %v", data)
}}'''),
    ("Typed struct with defer",
     '''type safeDefer{num} struct {{
	Key string `json:"key"`
}}

func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	body, _ := io.ReadAll(r.Body)
	var item safeDefer{num}
	defer func() {{
		json.Unmarshal(body, &item)
	}}()
}}'''),
    ("Typed gob decode",
     '''type safeGob{num} struct {{
	Value int
}}

func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	var val safeGob{num}
	gob.NewDecoder(r.Body).Decode(&val)
	fmt.Fprintf(w, "value: %d", val.Value)
}}'''),
    ("Typed struct from query param",
     '''type safeQuery{num} struct {{
	Filter string `json:"filter"`
}}

func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("data")
	var filter safeQuery{num}
	json.Unmarshal([]byte(raw), &filter)
	fmt.Fprintf(w, "filter: %s", filter.Filter)
}}'''),
]

CATEGORIES.append(("deser", "502", DESER_VULN, DESER_SAFE))

# ============================================================
# Open Redirect (CWE-601)
# ============================================================
REDIRECT_VULN = [
    ("Open redirect via http.Redirect",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.URL.Query().Get("url")
	http.Redirect(w, r, target, http.StatusFound)
}}'''),
    ("Open redirect via FormValue",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	next := r.FormValue("next")
	http.Redirect(w, r, next, http.StatusMovedPermanently)
}}'''),
    ("Open redirect via Header",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	location := r.Header.Get("X-Redirect")
	http.Redirect(w, r, location, http.StatusFound)
}}'''),
    ("Open redirect via channel",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.URL.Query().Get("redirect")
	ch := make(chan string, 1)
	ch <- target
	dest := <-ch
	http.Redirect(w, r, dest, http.StatusTemporaryRedirect)
}}'''),
    ("Open redirect via variable hop",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.FormValue("goto")
	dest := raw
	http.Redirect(w, r, dest, http.StatusFound)
}}'''),
    ("Open redirect via PostFormValue",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.PostFormValue("return_url")
	http.Redirect(w, r, target, http.StatusFound)
}}'''),
    ("Open redirect via Cookie",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	cookie, _ := r.Cookie("redirect_to")
	http.Redirect(w, r, cookie.Value, http.StatusFound)
}}'''),
    ("Open redirect via string concat",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	path := r.URL.Query().Get("path")
	target := "http://" + path
	http.Redirect(w, r, target, http.StatusFound)
}}'''),
    ("Open redirect via Location header",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.URL.Query().Get("dest")
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}}'''),
    ("Open redirect via goroutine-set header",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.FormValue("url")
	go func() {{
		http.Redirect(w, r, target, http.StatusFound)
	}}()
}}'''),
]

REDIRECT_SAFE = [
    ("Hardcoded redirect",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}}'''),
    ("Relative path only via HasPrefix",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.URL.Query().Get("next")
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {{
		http.Error(w, "bad redirect", 400)
		return
	}}
	http.Redirect(w, r, target, http.StatusFound)
}}'''),
    ("URL parse + host check",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.FormValue("url")
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Host != "" && parsed.Host != "example.com") {{
		http.Error(w, "forbidden", 403)
		return
	}}
	http.Redirect(w, r, parsed.String(), http.StatusFound)
}}'''),
    ("Allowlist of paths",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	dest := r.URL.Query().Get("dest")
	allowed := map[string]bool{{"/home": true, "/profile": true, "/settings": true}}
	if !allowed[dest] {{
		dest = "/home"
	}}
	http.Redirect(w, r, dest, http.StatusFound)
}}'''),
    ("Hardcoded via channel",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	ch := make(chan string, 1)
	ch <- "/home"
	dest := <-ch
	http.Redirect(w, r, dest, http.StatusFound)
}}'''),
    ("Hardcoded redirect in goroutine",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	go func() {{
		http.Redirect(w, r, "/login", http.StatusFound)
	}}()
}}'''),
    ("Path-only redirect with url.Parse",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.FormValue("next")
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() {{
		http.Error(w, "bad redirect", 400)
		return
	}}
	http.Redirect(w, r, parsed.Path, http.StatusFound)
}}'''),
    ("Integer-based page redirect",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("page")
	page, _ := strconv.Atoi(raw)
	dest := fmt.Sprintf("/results?page=%d", page)
	http.Redirect(w, r, dest, http.StatusFound)
}}'''),
    ("Hardcoded with defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	_ = r.FormValue("ignored")
	defer http.Redirect(w, r, "/done", http.StatusFound)
}}'''),
    ("Same-origin validated redirect",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	target := r.URL.Query().Get("next")
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host != "" {{
		target = "/"
	}}
	http.Redirect(w, r, target, http.StatusFound)
}}'''),
]

CATEGORIES.append(("redirect", "601", REDIRECT_VULN, REDIRECT_SAFE))

# ============================================================
# Log Injection (CWE-117)
# ============================================================
LOGINJ_VULN = [
    ("Log injection via log.Printf",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	user := r.URL.Query().Get("user")
	log.Printf("Login attempt: user=%s", user)
}}'''),
    ("Log injection via log.Println",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	action := r.FormValue("action")
	log.Println("Action performed: " + action)
}}'''),
    ("Log injection via fmt.Fprintf to logger",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	msg := r.URL.Query().Get("msg")
	logger := log.New(os.Stderr, "APP: ", log.LstdFlags)
	logger.Printf("User message: %s", msg)
}}'''),
    ("Log injection via channel",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	input := r.FormValue("data")
	ch := make(chan string, 1)
	ch <- input
	data := <-ch
	log.Printf("Received data: %s", data)
}}'''),
    ("Log injection via goroutine",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	ip := r.Header.Get("X-Forwarded-For")
	go func() {{
		log.Printf("Request from: %s", ip)
	}}()
}}'''),
    ("Log injection via Header",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	ua := r.Header.Get("User-Agent")
	log.Printf("User-Agent: %s", ua)
}}'''),
    ("Log injection via PostFormValue",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	comment := r.PostFormValue("comment")
	log.Printf("New comment: %s", comment)
}}'''),
    ("Log injection via defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	path := r.URL.Path
	defer log.Printf("Served path: %s", path)
}}'''),
    ("Log injection via Cookie",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	cookie, _ := r.Cookie("session_id")
	log.Printf("Session: %s", cookie.Value)
}}'''),
    ("Log injection via multiple assignments",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("ref")
	ref := raw
	log.Printf("Referrer: %s", ref)
}}'''),
]

LOGINJ_SAFE = [
    ("Structured logging with sanitized field",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	user := r.URL.Query().Get("user")
	safe := strings.ReplaceAll(user, "\\n", "")
	safe = strings.ReplaceAll(safe, "\\r", "")
	log.Printf("Login attempt: user=%s", safe)
}}'''),
    ("Hardcoded log message",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	log.Println("Health check endpoint hit")
}}'''),
    ("Integer-only log",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("id")
	id, _ := strconv.Atoi(raw)
	log.Printf("Lookup id=%d", id)
}}'''),
    ("Sanitized via strconv",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.FormValue("count")
	count, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {{
		return
	}}
	log.Printf("Count: %d", count)
}}'''),
    ("Hardcoded log via channel",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	ch := make(chan string, 1)
	ch <- "startup"
	msg := <-ch
	log.Printf("Event: %s", msg)
}}'''),
    ("Hardcoded in goroutine",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	go func() {{
		log.Println("Background task started")
	}}()
}}'''),
    ("Log with format verb %d only",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.URL.Query().Get("page")
	page, _ := strconv.Atoi(raw)
	log.Printf("Serving page %d", page)
}}'''),
    ("Hardcoded with defer",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	defer log.Println("Request completed")
}}'''),
    ("Boolean-only log",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	raw := r.FormValue("debug")
	debug, _ := strconv.ParseBool(raw)
	log.Printf("Debug mode: %t", debug)
}}'''),
    ("Quoted/escaped log output",
     '''func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	user := r.URL.Query().Get("user")
	log.Printf("Login attempt: user=%q", user)
}}'''),
]

CATEGORIES.append(("loginjection", "117", LOGINJ_VULN, LOGINJ_SAFE))


def imports_for_category(cat, is_vuln, body):
    """Determine needed imports from body content."""
    imports = set()
    imports.add('"net/http"')

    if "database/sql" in body or "sql." in body:
        imports.add('"database/sql"')
    if "fmt." in body:
        imports.add('"fmt"')
    if "os." in body:
        imports.add('"os"')
    if "io." in body or "io.ReadAll" in body or "io.Copy" in body:
        imports.add('"io"')
    if "exec." in body:
        imports.add('"os/exec"')
    if "filepath." in body:
        imports.add('"path/filepath"')
    if "strings." in body:
        imports.add('"strings"')
    if "strconv." in body:
        imports.add('"strconv"')
    if "url." in body:
        imports.add('"net/url"')
    if "net.Parse" in body or "net.Dial" in body:
        imports.add('"net"')
    if "template." in body and "htmltemplate." not in body:
        imports.add('"text/template"')
    if "htmltemplate." in body:
        imports.add('htmltemplate "html/template"')
    if "json." in body:
        imports.add('"encoding/json"')
    if "gob." in body:
        imports.add('"encoding/gob"')
    if "xml." in body:
        imports.add('"encoding/xml"')
    if "log." in body:
        imports.add('"log"')
    if "regexp." in body:
        imports.add('"regexp"')
    if "html." in body and "htmltemplate" not in body:
        imports.add('"html"')

    return sorted(imports)


def generate_file(num, handler_name, desc, body, imports):
    """Generate a single Go benchmark file."""
    import_block = "\n".join(f"\t{imp}" for imp in imports)
    return f'''package bench

import (
{import_block}
)

// {desc}
func {handler_name}(w http.ResponseWriter, r *http.Request) {{
	// placeholder
}}
'''


def main():
    os.makedirs(BASE_DIR, exist_ok=True)

    csv_rows = []
    file_num = 0

    for cat_name, cwe, vuln_templates, safe_templates in CATEGORIES:
        # Vulnerable cases
        for i, (desc, body_template) in enumerate(vuln_templates):
            file_num += 1
            test_name = f"BenchmarkTest{file_num:05d}"
            handler_name = f"Handler{file_num:05d}"

            body = body_template.format(handler_name=handler_name, num=file_num)
            imports = imports_for_category(cat_name, True, body)
            import_block = "\n".join(f"\t{imp}" for imp in imports)

            content = f'''package bench

import (
{import_block}
)

// {desc}
{body}
'''
            fpath = os.path.join(BASE_DIR, f"{test_name}.go")
            with open(fpath, "w") as f:
                f.write(content)

            csv_rows.append((test_name, cat_name, "true", cwe))

        # Safe cases
        for i, (desc, body_template) in enumerate(safe_templates):
            file_num += 1
            test_name = f"BenchmarkTest{file_num:05d}"
            handler_name = f"Handler{file_num:05d}"

            body = body_template.format(handler_name=handler_name, num=file_num)
            imports = imports_for_category(cat_name, False, body)
            import_block = "\n".join(f"\t{imp}" for imp in imports)

            content = f'''package bench

import (
{import_block}
)

// {desc}
{body}
'''
            fpath = os.path.join(BASE_DIR, f"{test_name}.go")
            with open(fpath, "w") as f:
                f.write(content)

            csv_rows.append((test_name, cat_name, "false", cwe))

    # Write CSV
    csv_path = os.path.join(BASE_DIR, "expectedresults.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        # No header row — matches OWASP format parsed by parseExpectedResults
        for row in csv_rows:
            writer.writerow(row)

    print(f"Generated {file_num} Go benchmark files in {BASE_DIR}")
    print(f"Generated {csv_path} with {len(csv_rows)} rows")
    print(f"Categories: {', '.join(c[0] for c in CATEGORIES)}")


if __name__ == "__main__":
    main()
