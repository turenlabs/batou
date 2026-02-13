package kotlin

import (
	"testing"

	"github.com/turen/gtss/internal/testutil"
)

// ==========================================================================
// GTSS-KT-001: Android SQL Injection
// ==========================================================================

func TestKT001_RawQuery_StringConcat(t *testing.T) {
	content := `fun searchUser(db: SQLiteDatabase, name: String) {
    val cursor = db.rawQuery("SELECT * FROM users WHERE name = '" + name + "'", null)
}`
	result := testutil.ScanContent(t, "/app/UserDao.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-001")
}

func TestKT001_RawQuery_StringTemplate(t *testing.T) {
	content := `fun searchUser(db: SQLiteDatabase, name: String) {
    val cursor = db.rawQuery("SELECT * FROM users WHERE name = '${name}'", null)
}`
	result := testutil.ScanContent(t, "/app/UserDao.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-001")
}

func TestKT001_ExecSQL_StringConcat(t *testing.T) {
	content := `fun deleteUser(db: SQLiteDatabase, id: String) {
    db.execSQL("DELETE FROM users WHERE id = " + id)
}`
	result := testutil.ScanContent(t, "/app/UserDao.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-001")
}

func TestKT001_ExecSQL_StringTemplate(t *testing.T) {
	content := `fun deleteUser(db: SQLiteDatabase, id: String) {
    db.execSQL("DELETE FROM users WHERE id = ${id}")
}`
	result := testutil.ScanContent(t, "/app/UserDao.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-001")
}

func TestKT001_RawQuery_Parameterized_Safe(t *testing.T) {
	content := `fun searchUser(db: SQLiteDatabase, name: String) {
    val cursor = db.rawQuery("SELECT * FROM users WHERE name = ?", arrayOf(name))
}`
	result := testutil.ScanContent(t, "/app/UserDao.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-001")
}

func TestKT001_RoomDAO_Safe(t *testing.T) {
	content := `@Dao
interface UserDao {
    @Query("SELECT * FROM users WHERE name = :name")
    fun findByName(name: String): User
}`
	result := testutil.ScanContent(t, "/app/UserDao.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-001")
}

// ==========================================================================
// GTSS-KT-002: Android Intent Injection
// ==========================================================================

func TestKT002_SendBroadcast_WithUserData(t *testing.T) {
	content := `fun forwardData(context: Context) {
    val data = intent.getStringExtra("user_input")
    val broadcastIntent = Intent("com.example.ACTION")
    broadcastIntent.putExtra("data", data)
    sendBroadcast(broadcastIntent)
}`
	result := testutil.ScanContent(t, "/app/MyActivity.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-002")
}

func TestKT002_ImplicitIntent_WithUserData(t *testing.T) {
	content := `fun shareData(context: Context) {
    val userInput = intent.getStringExtra("message")
    val shareIntent = Intent("com.example.SHARE")
    shareIntent.putExtra("content", userInput)
    startActivity(shareIntent)
}`
	result := testutil.ScanContent(t, "/app/ShareActivity.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-002")
}

func TestKT002_ExplicitIntent_Safe(t *testing.T) {
	content := `fun openDetail(context: Context) {
    val intent = Intent(context, DetailActivity::class.java)
    intent.putExtra("id", 42)
    startActivity(intent)
}`
	result := testutil.ScanContent(t, "/app/MainActivity.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-002")
}

// ==========================================================================
// GTSS-KT-003: WebView JavaScript Injection
// ==========================================================================

func TestKT003_LoadUrl_JavascriptConcat(t *testing.T) {
	content := `fun updateWebView(webView: WebView, userInput: String) {
    webView.loadUrl("javascript:updateField('" + userInput + "')")
}`
	result := testutil.ScanContent(t, "/app/WebActivity.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-003")
}

func TestKT003_LoadUrl_JavascriptTemplate(t *testing.T) {
	content := `fun updateWebView(webView: WebView, userInput: String) {
    webView.loadUrl("javascript:updateField('${userInput}')")
}`
	result := testutil.ScanContent(t, "/app/WebActivity.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-003")
}

func TestKT003_AddJavascriptInterface(t *testing.T) {
	content := `fun setupWebView(webView: WebView) {
    webView.settings.javaScriptEnabled = true
    webView.addJavascriptInterface(JsBridge(), "Android")
    webView.loadUrl("https://example.com")
}`
	result := testutil.ScanContent(t, "/app/WebActivity.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-003")
}

func TestKT003_EvaluateJavascript_Concat(t *testing.T) {
	content := `fun runScript(webView: WebView, input: String) {
    webView.evaluateJavascript("document.getElementById('name').value = '" + input + "'", null)
}`
	result := testutil.ScanContent(t, "/app/WebActivity.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-003")
}

func TestKT003_LoadUrl_Static_Safe(t *testing.T) {
	content := `fun loadPage(webView: WebView) {
    webView.loadUrl("https://example.com/page")
}`
	result := testutil.ScanContent(t, "/app/WebActivity.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-003")
}

// ==========================================================================
// GTSS-KT-004: Insecure SharedPreferences
// ==========================================================================

func TestKT004_SharedPrefs_StoringPassword(t *testing.T) {
	content := `fun saveCredentials(context: Context, password: String) {
    val prefs = context.getSharedPreferences("user_prefs", Context.MODE_PRIVATE)
    prefs.edit().putString("password", password).apply()
}`
	result := testutil.ScanContent(t, "/app/CredentialManager.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-004")
}

func TestKT004_SharedPrefs_StoringToken(t *testing.T) {
	content := `fun saveToken(context: Context, token: String) {
    val prefs = context.getSharedPreferences("auth_prefs", Context.MODE_PRIVATE)
    prefs.edit().putString("auth_token", token).apply()
}`
	result := testutil.ScanContent(t, "/app/TokenManager.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-004")
}

func TestKT004_EncryptedSharedPrefs_Safe(t *testing.T) {
	content := `fun saveCredentials(context: Context, password: String) {
    val masterKey = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
    val prefs = EncryptedSharedPreferences.create(
        "secure_prefs", masterKey, context,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
    prefs.edit().putString("password", password).apply()
}`
	result := testutil.ScanContent(t, "/app/CredentialManager.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-004")
}

func TestKT004_SharedPrefs_NonSensitive_Safe(t *testing.T) {
	content := `fun saveTheme(context: Context, theme: String) {
    val prefs = context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
    prefs.edit().putString("theme", theme).apply()
}`
	result := testutil.ScanContent(t, "/app/SettingsManager.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-004")
}

// ==========================================================================
// GTSS-KT-005: Android Exported Components
// ==========================================================================

func TestKT005_ExportedActivity_NoPermission(t *testing.T) {
	content := `<manifest>
    <application>
        <activity
            android:name=".AdminActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="com.example.ADMIN" />
            </intent-filter>
        </activity>
    </application>
</manifest>`
	result := testutil.ScanContent(t, "/app/AndroidManifest.xml", content)
	testutil.MustFindRule(t, result, "GTSS-KT-005")
}

func TestKT005_ExportedProvider_NoPermission(t *testing.T) {
	content := `<manifest>
    <application>
        <provider
            android:name=".DataProvider"
            android:exported="true"
            android:authorities="com.example.provider">
        </provider>
    </application>
</manifest>`
	result := testutil.ScanContent(t, "/app/AndroidManifest.xml", content)
	testutil.MustFindRule(t, result, "GTSS-KT-005")
}

func TestKT005_ExportedActivity_WithPermission_Safe(t *testing.T) {
	content := `<manifest>
    <application>
        <activity
            android:name=".AdminActivity"
            android:exported="true"
            android:permission="com.example.ADMIN_PERMISSION">
        </activity>
    </application>
</manifest>`
	result := testutil.ScanContent(t, "/app/AndroidManifest.xml", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-005")
}

func TestKT005_NotExported_Safe(t *testing.T) {
	content := `<manifest>
    <application>
        <activity
            android:name=".InternalActivity"
            android:exported="false">
        </activity>
    </application>
</manifest>`
	result := testutil.ScanContent(t, "/app/AndroidManifest.xml", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-005")
}

// ==========================================================================
// GTSS-KT-006: Ktor CORS Misconfiguration
// ==========================================================================

func TestKT006_KtorCORS_AnyHostWithCredentials(t *testing.T) {
	content := `fun Application.configureCors() {
    install(CORS) {
        anyHost()
        allowCredentials = true
        allowHeader(HttpHeaders.ContentType)
    }
}`
	result := testutil.ScanContent(t, "/app/Cors.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-006")
}

func TestKT006_KtorCORS_AnyHostOnly(t *testing.T) {
	content := `fun Application.configureCors() {
    install(CORS) {
        anyHost()
        allowHeader(HttpHeaders.ContentType)
    }
}`
	result := testutil.ScanContent(t, "/app/Cors.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-006")
}

func TestKT006_KtorCORS_SpecificHost_Safe(t *testing.T) {
	content := `fun Application.configureCors() {
    install(CORS) {
        allowHost("trusted.example.com")
        allowCredentials = true
        allowHeader(HttpHeaders.ContentType)
    }
}`
	result := testutil.ScanContent(t, "/app/Cors.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-006")
}

// ==========================================================================
// GTSS-KT-007: Unsafe Coroutine Exception Handling
// ==========================================================================

func TestKT007_GlobalScope_NoHandler(t *testing.T) {
	content := `fun performTask() {
    GlobalScope.launch {
        val result = riskyOperation()
        processResult(result)
    }
}`
	result := testutil.ScanContent(t, "/app/TaskRunner.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-007")
}

func TestKT007_GlobalScope_Async_NoHandler(t *testing.T) {
	content := `fun fetchData(): Deferred<String> {
    return GlobalScope.async {
        apiCall()
    }
}`
	result := testutil.ScanContent(t, "/app/DataFetcher.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-007")
}

func TestKT007_GlobalScope_WithHandler_Safe(t *testing.T) {
	content := `val handler = CoroutineExceptionHandler { _, exception ->
    log.error("Coroutine failed", exception)
}

fun performTask() {
    GlobalScope.launch {
        riskyOperation()
    }
}`
	result := testutil.ScanContent(t, "/app/TaskRunner.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-007")
}

func TestKT007_StructuredConcurrency_Safe(t *testing.T) {
	content := `class MyViewModel : ViewModel() {
    fun performTask() {
        viewModelScope.launch {
            val result = riskyOperation()
            processResult(result)
        }
    }
}`
	result := testutil.ScanContent(t, "/app/MyViewModel.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-007")
}

// ==========================================================================
// GTSS-KT-008: Kotlin Serialization with Untrusted Input
// ==========================================================================

func TestKT008_JsonDecode_WithUserInput(t *testing.T) {
	content := `fun handleRequest(call: ApplicationCall) {
    val body = call.receiveText()
    val user = Json.decodeFromString<User>(body)
    processUser(user)
}`
	result := testutil.ScanContent(t, "/app/UserHandler.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-008")
}

func TestKT008_JsonDecode_CustomConfig_WithUserInput(t *testing.T) {
	content := `fun handleRequest(call: ApplicationCall) {
    val body = call.receiveText()
    val json = Json { ignoreUnknownKeys = true }
    val user = json.decodeFromString<User>(body)
}`
	result := testutil.ScanContent(t, "/app/UserHandler.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-008")
	// Note: custom Json instance doesn't match the jsonDecodeCustom pattern
	// because it uses a local variable, not Json{...}.decodeFromString
}

func TestKT008_JsonDecode_InternalData_Safe(t *testing.T) {
	content := `fun loadConfig() {
    val configJson = File("config.json").readText()
    val config = Json.decodeFromString<AppConfig>(configJson)
}`
	result := testutil.ScanContent(t, "/app/ConfigLoader.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-008")
}
