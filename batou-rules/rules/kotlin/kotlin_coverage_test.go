package kotlin

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// scanKT builds a ScanContext and runs a single rule's Scan directly. This
// covers FP-gate branches precisely without depending on rule registration
// order, and is the canonical way to exercise an individual rule's Scan().
func scanKT(r rules.Rule, path, content string) []rules.Finding {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	ctx := &rules.ScanContext{
		FilePath: path,
		Content:  content,
		Language: rules.LangKotlin,
		IsNew:    true,
	}
	return r.Scan(ctx)
}

func hasRule(findings []rules.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// ==========================================================================
// BATOU-KT-017: Kotlin Runtime.exec with string concatenation
// ==========================================================================

func TestKT017_RuntimeExec_Concat(t *testing.T) {
	content := `fun ping(host: String) {
    Runtime.getRuntime().exec("ping " + host)
}`
	result := testutil.ScanContent(t, "/app/Net.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-017")
}

func TestKT017_RuntimeExec_Interp(t *testing.T) {
	content := `fun ping(host: String) {
    Runtime.getRuntime().exec("ping ${host}")
}`
	result := testutil.ScanContent(t, "/app/Net.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-017")
}

func TestKT017_ProcessBuilder_Concat(t *testing.T) {
	content := `fun run(arg: String) {
    ProcessBuilder("cmd " + arg).start()
}`
	result := testutil.ScanContent(t, "/app/Net.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-017")
}

func TestKT017_StaticCommand_Safe(t *testing.T) {
	content := `fun listFiles() {
    Runtime.getRuntime().exec("ls -la")
}`
	result := testutil.ScanContent(t, "/app/Net.kt", content)
	testutil.MustNotFindRule(t, result, "BATOU-KT-017")
}

func TestKT017_CommentSkipped(t *testing.T) {
	// Comment lines are skipped; nothing should fire.
	content := `// Runtime.getRuntime().exec("ping " + host)
fun noop() {}`
	got := scanKT(&KotlinRuntimeExec{}, "/app/Net.kt", content)
	if hasRule(got, "BATOU-KT-017") {
		t.Fatalf("comment line should be skipped, got %v", got)
	}
}

// ==========================================================================
// BATOU-KT-018: Kotlin WebView JavaScript enabled without protection
// ==========================================================================

func TestKT018_AddJavascriptInterface_JSEnabled(t *testing.T) {
	content := `fun setup(webView: WebView) {
    webView.settings.javaScriptEnabled = true
    webView.addJavascriptInterface(Bridge(), "Android")
}`
	result := testutil.ScanContent(t, "/app/Web.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-018")
}

func TestKT018_JSEnabled_NoWebViewClient(t *testing.T) {
	// JS enabled and no WebViewClient => medium finding fires.
	content := `fun setup(webView: WebView) {
    webView.settings.javaScriptEnabled = true
}`
	got := scanKT(&KotlinWebViewJS{}, "/app/Web.kt", content)
	if !hasRule(got, "BATOU-KT-018") {
		t.Fatalf("expected BATOU-KT-018 for JS-enabled without WebViewClient, got %v", got)
	}
}

func TestKT018_JSEnabled_WithWebViewClient_Safe(t *testing.T) {
	// WebViewClient present suppresses the medium (no-WebViewClient) branch,
	// and there is no addJavascriptInterface, so nothing fires.
	content := `fun setup(webView: WebView) {
    webView.settings.javaScriptEnabled = true
    webView.webViewClient = MyWebViewClient()
}`
	got := scanKT(&KotlinWebViewJS{}, "/app/Web.kt", content)
	if hasRule(got, "BATOU-KT-018") {
		t.Fatalf("WebViewClient present should suppress KT-018, got %v", got)
	}
}

func TestKT018_JSDisabled_Safe(t *testing.T) {
	// Rule bails entirely when JS is not enabled.
	content := `fun setup(webView: WebView) {
    webView.addJavascriptInterface(Bridge(), "Android")
}`
	got := scanKT(&KotlinWebViewJS{}, "/app/Web.kt", content)
	if got != nil {
		t.Fatalf("rule should bail when JS not enabled, got %v", got)
	}
}

// ==========================================================================
// BATOU-KT-019: Kotlin SharedPreferences storing sensitive data
// ==========================================================================

func TestKT019_PutString_SensitiveKey(t *testing.T) {
	content := `fun save(context: Context, token: String) {
    val prefs = context.getSharedPreferences("p", 0)
    prefs.edit().putString("auth_token", token).apply()
}`
	result := testutil.ScanContent(t, "/app/Prefs.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-019")
}

func TestKT019_PreferenceManager_Source(t *testing.T) {
	content := `fun save(context: Context, secret: String) {
    val prefs = PreferenceManager.getDefaultSharedPreferences(context)
    prefs.edit().putString("api_secret_value", secret).apply()
}`
	result := testutil.ScanContent(t, "/app/Prefs.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-019")
}

func TestKT019_NoSharedPrefs_Bail(t *testing.T) {
	// No SharedPreferences usage => rule bails (returns nil).
	content := `fun save(token: String) {
    println("token: $token")
}`
	got := scanKT(&KotlinSharedPrefSensitive{}, "/app/Prefs.kt", content)
	if got != nil {
		t.Fatalf("rule should bail without SharedPreferences, got %v", got)
	}
}

func TestKT019_NonSensitiveKey_Safe(t *testing.T) {
	content := `fun save(context: Context, theme: String) {
    val prefs = context.getSharedPreferences("p", 0)
    prefs.edit().putString("theme_name", theme).apply()
}`
	result := testutil.ScanContent(t, "/app/Prefs.kt", content)
	testutil.MustNotFindRule(t, result, "BATOU-KT-019")
}

// ==========================================================================
// BATOU-KT-020: Kotlin Intent with user-controlled component
// ==========================================================================

func TestKT020_SetClassName_Variable(t *testing.T) {
	content := `fun redirect(pkg: String, cls: String) {
    val intent = Intent()
    intent.setClassName(pkg, cls)
    startActivity(intent)
}`
	result := testutil.ScanContent(t, "/app/Redirect.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-020")
}

func TestKT020_SetComponent_Variable(t *testing.T) {
	content := `fun redirect(comp: ComponentName) {
    val intent = Intent()
    intent.setComponent(comp)
    startActivity(intent)
}`
	result := testutil.ScanContent(t, "/app/Redirect.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-020")
}

func TestKT020_NoSetComponent_Bail(t *testing.T) {
	content := `fun open(context: Context) {
    val intent = Intent(context, DetailActivity::class.java)
    startActivity(intent)
}`
	got := scanKT(&KotlinIntentRedirect{}, "/app/Redirect.kt", content)
	if got != nil {
		t.Fatalf("rule should bail without setComponent/setClassName, got %v", got)
	}
}

// ==========================================================================
// BATOU-KT-021: Kotlin exported ContentProvider without permissions
// ==========================================================================

// KT-021 is Kotlin-only (Languages() == LangKotlin), but AndroidManifest.xml
// detects as LangAny in testutil, so ScanContent never runs it. Exercise the
// rule's Scan() directly.
func TestKT021_ExportedProvider_NoPermission(t *testing.T) {
	content := `<manifest>
    <application>
        <provider
            android:name=".DataProvider"
            android:exported="true"
            android:authorities="com.example.data" />
    </application>
</manifest>`
	got := scanKT(&KotlinExportedProvider{}, "/app/AndroidManifest.xml", content)
	if !hasRule(got, "BATOU-KT-021") {
		t.Fatalf("expected BATOU-KT-021, got %v", got)
	}
}

func TestKT021_ExportedProvider_WithPermission_Safe(t *testing.T) {
	content := `<manifest>
    <application>
        <provider
            android:name=".DataProvider"
            android:exported="true"
            android:readPermission="com.example.READ"
            android:writePermission="com.example.WRITE" />
    </application>
</manifest>`
	got := scanKT(&KotlinExportedProvider{}, "/app/AndroidManifest.xml", content)
	if hasRule(got, "BATOU-KT-021") {
		t.Fatalf("provider with permissions should be safe, got %v", got)
	}
}

func TestKT021_NoProviderTag_Bail(t *testing.T) {
	content := `<manifest>
    <application android:exported="true" />
</manifest>`
	got := scanKT(&KotlinExportedProvider{}, "/app/AndroidManifest.xml", content)
	if got != nil {
		t.Fatalf("rule should bail without <provider tag, got %v", got)
	}
}

// ==========================================================================
// BATOU-KT-022: Kotlin insecure broadcast receiver
// ==========================================================================

func TestKT022_SendBroadcast_NoPermission(t *testing.T) {
	content := `fun notifyAll(intent: Intent) {
    sendBroadcast(intent)
}`
	result := testutil.ScanContent(t, "/app/Bcast.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-022")
}

func TestKT022_RegisterReceiver_NoPermission(t *testing.T) {
	content := `fun listen(receiver: BroadcastReceiver, filter: IntentFilter) {
    registerReceiver(receiver, filter)
}`
	result := testutil.ScanContent(t, "/app/Bcast.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-022")
}

func TestKT022_NoBroadcast_Safe(t *testing.T) {
	content := `fun doNothing() {
    val x = 1
}`
	result := testutil.ScanContent(t, "/app/Bcast.kt", content)
	testutil.MustNotFindRule(t, result, "BATOU-KT-022")
}

// ==========================================================================
// BATOU-KT-023: Kotlin SQL injection in Room raw query
// ==========================================================================

func TestKT023_SimpleSQLiteQuery_Concat(t *testing.T) {
	content := `fun search(id: String) {
    val q = SimpleSQLiteQuery("SELECT * FROM t WHERE id = " + id)
    dao.rawQuery(q)
}`
	result := testutil.ScanContent(t, "/app/Dao.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-023")
}

func TestKT023_SimpleSQLiteQuery_Interp(t *testing.T) {
	content := `fun search(name: String) {
    val q = SimpleSQLiteQuery("SELECT * FROM t WHERE name = '${name}'")
    dao.rawQuery(q)
}`
	result := testutil.ScanContent(t, "/app/Dao.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-023")
}

func TestKT023_Parameterized_Safe(t *testing.T) {
	content := `fun search(id: String) {
    val q = SimpleSQLiteQuery("SELECT * FROM t WHERE id = ?", arrayOf(id))
    dao.rawQuery(q)
}`
	result := testutil.ScanContent(t, "/app/Dao.kt", content)
	testutil.MustNotFindRule(t, result, "BATOU-KT-023")
}

// ==========================================================================
// BATOU-KT-024: Kotlin certificate pinning bypass (trust all)
// ==========================================================================

func TestKT024_HostnameVerifier_AlwaysTrue(t *testing.T) {
	content := `fun configure(builder: OkHttpClient.Builder) {
    builder.hostnameVerifier(HostnameVerifier { _, _ -> true })
}`
	result := testutil.ScanContent(t, "/app/Tls.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-024")
}

func TestKT024_EmptyCheckServerTrusted(t *testing.T) {
	content := `val tm = object : X509TrustManager {
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}`
	result := testutil.ScanContent(t, "/app/Tls.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-024")
}

func TestKT024_CheckServer_NoTrustManagerInFile_Safe(t *testing.T) {
	// checkServerTrusted line present but the file has no TrustManager token,
	// so the second branch's GMatchFile guard fails and nothing fires.
	content := `fun verify(chain: Array<Cert>, authType: String) {
    checkServerTrusted(chain, authType)
}`
	got := scanKT(&KotlinTrustAllCerts{}, "/app/Tls.kt", content)
	if hasRule(got, "BATOU-KT-024") {
		t.Fatalf("no TrustManager token in file should suppress KT-024, got %v", got)
	}
}

func TestKT024_NoTlsBypass_Safe(t *testing.T) {
	content := `fun normal(): Int {
    return 42
}`
	result := testutil.ScanContent(t, "/app/Tls.kt", content)
	testutil.MustNotFindRule(t, result, "BATOU-KT-024")
}

// ==========================================================================
// BATOU-KT-025: Kotlin JDBC SQL injection
// ==========================================================================

func TestKT025_ExecuteQuery_Concat(t *testing.T) {
	content := `fun Route.users() {
    get("/u") {
        val id = call.parameters["id"]
        val stmt = connection.createStatement()
        val rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + id)
        call.respond(rs)
    }
}`
	result := testutil.ScanContent(t, "/app/Routes.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-025")
}

func TestKT025_SQLStringTemplate(t *testing.T) {
	content := `fun Route.users() {
    get("/u") {
        val id = call.parameters["id"]
        val query = "SELECT * FROM users WHERE id = $id"
        val rs = connection.createStatement().executeQuery(query)
        call.respond(rs)
    }
}`
	result := testutil.ScanContent(t, "/app/Routes.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-025")
}

func TestKT025_PreparedStatement_Safe(t *testing.T) {
	content := `fun Route.users() {
    get("/u") {
        val id = call.parameters["id"]
        val stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?")
        stmt.setString(1, id)
        val rs = stmt.executeQuery()
        call.respond(rs)
    }
}`
	result := testutil.ScanContent(t, "/app/Routes.kt", content)
	testutil.MustNotFindRule(t, result, "BATOU-KT-025")
}

func TestKT025_NoSQL_Bail(t *testing.T) {
	content := `fun Route.users() {
    get("/u") {
        val id = call.parameters["id"]
        call.respond(id)
    }
}`
	got := scanKT(&KotlinJDBCSQLInjection{}, "/app/Routes.kt", content)
	if got != nil {
		t.Fatalf("rule should bail without executeQuery/createStatement, got %v", got)
	}
}

func TestKT025_NoUserInput_Bail(t *testing.T) {
	// SQL function present but no user input => rule bails.
	content := `fun loadAll() {
    val stmt = connection.createStatement()
    val rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + ADMIN_ID)
}`
	got := scanKT(&KotlinJDBCSQLInjection{}, "/app/Routes.kt", content)
	if got != nil {
		t.Fatalf("rule should bail without user input, got %v", got)
	}
}

func TestKT025_IntCoercion_Safe(t *testing.T) {
	content := `fun Route.users() {
    get("/u") {
        val id = call.parameters["id"]
        val n = id.toIntOrNull() ?: 0
        val rs = connection.createStatement().executeQuery("SELECT * FROM users WHERE id = " + n)
        call.respond(rs)
    }
}`
	result := testutil.ScanContent(t, "/app/Routes.kt", content)
	testutil.MustNotFindRule(t, result, "BATOU-KT-025")
}

// ==========================================================================
// BATOU-KT-026: Kotlin XSS via HTML response
// ==========================================================================

func TestKT026_RespondTextHTML_UserInput(t *testing.T) {
	content := `fun Route.greet() {
    get("/hello") {
        val name = call.parameters["name"]
        call.respondText("<h1>Hello $name</h1>", ContentType.Text.Html)
    }
}`
	result := testutil.ScanContent(t, "/app/Web.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-026")
}

func TestKT026_Escaped_Safe(t *testing.T) {
	content := `fun Route.greet() {
    get("/hello") {
        val name = call.parameters["name"]
        val safe = htmlEscape(name)
        call.respondText("<h1>Hello $safe</h1>", ContentType.Text.Html)
    }
}`
	result := testutil.ScanContent(t, "/app/Web.kt", content)
	testutil.MustNotFindRule(t, result, "BATOU-KT-026")
}

func TestKT026_JsonContentType_Safe(t *testing.T) {
	content := `fun Route.api() {
    get("/data") {
        val q = call.parameters["q"]
        call.respondText("{\"q\":\"$q\"}", ContentType.Application.Json)
    }
}`
	result := testutil.ScanContent(t, "/app/Web.kt", content)
	testutil.MustNotFindRule(t, result, "BATOU-KT-026")
}

func TestKT026_NoRespondText_Bail(t *testing.T) {
	content := `fun Route.api() {
    get("/data") {
        val q = call.parameters["q"]
        call.respond(q)
    }
}`
	got := scanKT(&KotlinXSSHTMLResponse{}, "/app/Web.kt", content)
	if got != nil {
		t.Fatalf("rule should bail without respondText/respondHtml/return HTML, got %v", got)
	}
}

func TestKT026_ReturnHTML_ServletInput(t *testing.T) {
	content := `@GetMapping("/page")
fun page(@RequestParam name: String): String {
    return "<div>$name</div>"
}`
	result := testutil.ScanContent(t, "/app/Page.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-026")
}

// ==========================================================================
// BATOU-KT-027: Kotlin command injection (broader)
// ==========================================================================

func TestKT027_RuntimeExec_Interp_UserInput(t *testing.T) {
	content := `fun Route.run() {
    get("/ping") {
        val host = call.parameters["host"]
        Runtime.getRuntime().exec("ping $host")
    }
}`
	result := testutil.ScanContent(t, "/app/Cmd.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-027")
}

func TestKT027_ProcessBuilderShell_UserInput(t *testing.T) {
	content := `fun Route.run() {
    get("/exec") {
        val cmd = call.parameters["cmd"]
        ProcessBuilder("/bin/sh", "-c", "echo $cmd").start()
    }
}`
	result := testutil.ScanContent(t, "/app/Cmd.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-027")
}

func TestKT027_NoExec_Bail(t *testing.T) {
	content := `fun Route.run() {
    get("/x") {
        val cmd = call.parameters["cmd"]
        println(cmd)
    }
}`
	got := scanKT(&KotlinCommandInjection{}, "/app/Cmd.kt", content)
	if got != nil {
		t.Fatalf("rule should bail without exec/ProcessBuilder, got %v", got)
	}
}

func TestKT027_NoUserInput_Bail(t *testing.T) {
	content := `fun staticRun() {
    Runtime.getRuntime().exec("ls -la /tmp")
}`
	got := scanKT(&KotlinCommandInjection{}, "/app/Cmd.kt", content)
	if got != nil {
		t.Fatalf("rule should bail without user input, got %v", got)
	}
}

func TestKT027_Allowlist_Safe(t *testing.T) {
	content := `fun Route.run() {
    get("/exec") {
        val cmd = call.parameters["cmd"]
        val allowed = setOf("status", "version")
        if (cmd in allowed) {
            Runtime.getRuntime().exec("svc $cmd")
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Cmd.kt", content)
	testutil.MustNotFindRule(t, result, "BATOU-KT-027")
}

// ==========================================================================
// BATOU-KT-028: Kotlin path traversal
// ==========================================================================

func TestKT028_FileWithConcat_UserInput(t *testing.T) {
	content := `fun Route.read() {
    get("/file") {
        val name = call.parameters["name"]
        val f = File("/data/" + name)
        call.respondText(f.readText())
    }
}`
	result := testutil.ScanContent(t, "/app/Files.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-028")
}

func TestKT028_FileWithInterp_UserInput(t *testing.T) {
	content := `fun Route.read() {
    get("/file") {
        val name = call.parameters["name"]
        val f = File("/data/$name")
        call.respondText(f.readText())
    }
}`
	result := testutil.ScanContent(t, "/app/Files.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-028")
}

func TestKT028_CanonicalCheck_Safe(t *testing.T) {
	content := `fun Route.read() {
    get("/file") {
        val name = call.parameters["name"]
        val base = File("/data")
        val resolved = File(base, name).canonicalFile
        require(resolved.path.startsWith(base.canonicalPath))
        call.respondText(resolved.readText())
    }
}`
	result := testutil.ScanContent(t, "/app/Files.kt", content)
	testutil.MustNotFindRule(t, result, "BATOU-KT-028")
}

func TestKT028_NoFile_Bail(t *testing.T) {
	content := `fun Route.read() {
    get("/x") {
        val name = call.parameters["name"]
        call.respondText(name)
    }
}`
	got := scanKT(&KotlinPathTraversal{}, "/app/Files.kt", content)
	if got != nil {
		t.Fatalf("rule should bail without file operations, got %v", got)
	}
}

func TestKT028_NoUserInput_Bail(t *testing.T) {
	content := `fun loadConfig() {
    val f = File("/etc/app/config.json")
    f.readText()
}`
	got := scanKT(&KotlinPathTraversal{}, "/app/Files.kt", content)
	if got != nil {
		t.Fatalf("rule should bail without user input, got %v", got)
	}
}

// ==========================================================================
// BATOU-KT-029: Kotlin open redirect
// ==========================================================================

func TestKT029_RespondRedirect_UserInput(t *testing.T) {
	content := `fun Route.go() {
    get("/redirect") {
        val target = call.parameters["url"]
        call.respondRedirect(target)
    }
}`
	result := testutil.ScanContent(t, "/app/Redir.kt", content)
	testutil.MustFindRule(t, result, "BATOU-KT-029")
}

func TestKT029_HardcodedRedirect_Safe(t *testing.T) {
	content := `fun Route.go() {
    get("/redirect") {
        val target = call.parameters["url"]
        call.respondRedirect("/dashboard")
    }
}`
	result := testutil.ScanContent(t, "/app/Redir.kt", content)
	testutil.MustNotFindRule(t, result, "BATOU-KT-029")
}

func TestKT029_URLValidation_Safe(t *testing.T) {
	content := `fun Route.go() {
    get("/redirect") {
        val target = call.parameters["url"]
        if (target != null && target.startsWith("/")) {
            call.respondRedirect(target)
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Redir.kt", content)
	testutil.MustNotFindRule(t, result, "BATOU-KT-029")
}

func TestKT029_NoRedirect_Bail(t *testing.T) {
	content := `fun Route.go() {
    get("/x") {
        val target = call.parameters["url"]
        call.respond(target)
    }
}`
	got := scanKT(&KotlinOpenRedirect{}, "/app/Redir.kt", content)
	if got != nil {
		t.Fatalf("rule should bail without respondRedirect/sendRedirect, got %v", got)
	}
}

// ==========================================================================
// Helper / unexported function coverage
// ==========================================================================

func TestHelper_IsTypedDecodeFromString(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{`val u = Json.decodeFromString<User>(body)`, true},
		{`val u = Json.decodeFromString<Any>(body)`, false},
		{`val u = Json.decodeFromString<Object>(body)`, false},
		{`val u = Json.decodeFromString<>(body)`, false},
		{`val u = Json.decodeFromString(body)`, false}, // no type param
		{`val u = something.parse(body)`, false},       // no decodeFromString
		{`val u = Json.decodeFromString<List<Int>>(body)`, true},
	}
	for _, c := range cases {
		if got := isTypedDecodeFromString(c.line); got != c.want {
			t.Errorf("isTypedDecodeFromString(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestHelper_IsComment(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"// a comment", true},
		{"* javadoc line", true},
		{"/* block start", true},
		{"<!-- xml comment", true},
		{"val x = 1", false},
		{"  not trimmed", false},
	}
	for _, c := range cases {
		if got := isComment(c.line); got != c.want {
			t.Errorf("isComment(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestHelper_Truncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate short = %q", got)
	}
	long := strings.Repeat("a", 130)
	got := truncate(long, 120)
	if len(got) != 123 || !strings.HasSuffix(got, "...") {
		t.Errorf("truncate long: len=%d suffix=%v", len(got), strings.HasSuffix(got, "..."))
	}
	// Exactly at boundary: not truncated.
	exact := strings.Repeat("b", 120)
	if got := truncate(exact, 120); got != exact {
		t.Errorf("truncate at boundary should not append ellipsis")
	}
}

func TestHelper_SurroundingContext(t *testing.T) {
	lines := []string{"l0", "l1", "l2", "l3", "l4"}
	// Around index 2 with radius 1 => l1,l2,l3.
	got := surroundingContext(lines, 2, 1)
	if got != "l1\nl2\nl3" {
		t.Errorf("surroundingContext mid = %q", got)
	}
	// Clamp at start.
	if got := surroundingContext(lines, 0, 2); got != "l0\nl1\nl2" {
		t.Errorf("surroundingContext start = %q", got)
	}
	// Clamp at end.
	if got := surroundingContext(lines, 4, 2); got != "l2\nl3\nl4" {
		t.Errorf("surroundingContext end = %q", got)
	}
}

func TestHelper_HasVariableInterp(t *testing.T) {
	if !hasVariableInterp(`"echo $name"`) {
		t.Error("expected hasVariableInterp true for quoted $var")
	}
	if hasVariableInterp(`plain text`) {
		t.Error("expected false without $")
	}
	if hasVariableInterp(`$novars`) {
		t.Error("expected false: $ present but no quote")
	}
}

func TestHelper_HasVariableInArgs(t *testing.T) {
	// True when arrayOf/listOf is present with a comma: the segment before the
	// first comma is `arrayOf("..."` which itself contains lowercase letters and
	// does not start with a quote, so the helper returns true. This is the
	// rule's actual (coarse) behavior — exercised here, not idealized.
	if !hasVariableInArgs(`arrayOf("sh", "-c", cmd)`) {
		t.Error("expected true: arrayOf with comma-separated args")
	}
	if !hasVariableInArgs(`arrayOf("ls", "-la")`) {
		t.Error("expected true: arrayOf prefix segment trips the lowercase check")
	}
	if !hasVariableInArgs(`listOf("a", b)`) {
		t.Error("expected true: listOf with variable")
	}
	// False only when there is no arrayOf/listOf at all (any arrayOf(/listOf(
	// segment already contains the lowercase prefix text and so always trips).
	if hasVariableInArgs(`exec("ls")`) {
		t.Error("expected false: no arrayOf/listOf")
	}
	if hasVariableInArgs(`println("hi")`) {
		t.Error("expected false: no arrayOf/listOf")
	}
}

func TestHelper_IsHardcodedFilePath(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{`val f = File("/var/data/config.json")`, true},
		{`val f = File(userInput)`, false},
		{`val f = File("/data/" + name)`, false},
		{`val f = File("/data/$name")`, false},
		{`val x = readText()`, false}, // no File(
	}
	for _, c := range cases {
		if got := isHardcodedFilePath(c.line); got != c.want {
			t.Errorf("isHardcodedFilePath(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// ==========================================================================
// CWE / severity sanity on a representative finding
// ==========================================================================

func TestKT024_CWEAndSeverity(t *testing.T) {
	content := `fun configure(b: OkHttpClient.Builder) {
    b.hostnameVerifier(HostnameVerifier { _, _ -> true })
}`
	got := scanKT(&KotlinTrustAllCerts{}, "/app/Tls.kt", content)
	if len(got) == 0 {
		t.Fatal("expected a KT-024 finding")
	}
	f := got[0]
	if f.CWEID != "CWE-295" {
		t.Errorf("CWEID = %q, want CWE-295", f.CWEID)
	}
	if f.Severity != rules.Critical {
		t.Errorf("Severity = %v, want Critical", f.Severity)
	}
}
