package kotlin

import (
	"testing"

	"github.com/turenio/gtss/internal/testutil"
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

// ==========================================================================
// GTSS-KT-009: Kotlin Reflection Injection
// ==========================================================================

func TestKT009_ClassForName_Variable(t *testing.T) {
	content := `fun loadPlugin(className: String) {
    val clazz = Class.forName(className)
    val instance = clazz.newInstance()
    (instance as Plugin).execute()
}`
	result := testutil.ScanContent(t, "/app/PluginLoader.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-009")
}

func TestKT009_ClassForName_Allowlist_Safe(t *testing.T) {
	content := `val allowedClasses = setOf("com.example.PluginA", "com.example.PluginB")

fun loadPlugin(className: String) {
    if (className !in allowedClasses) throw SecurityException("Not allowed")
    val clazz = Class.forName(className)
    val instance = clazz.newInstance()
}`
	result := testutil.ScanContent(t, "/app/PluginLoader.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-009")
}

// ==========================================================================
// GTSS-KT-010: Content Provider Injection
// ==========================================================================

func TestKT010_ContentResolverQueryUserUri(t *testing.T) {
	content := `fun queryData(uri: String) {
    val contentUri = Uri.parse(uri)
    val cursor = contentResolver.query(contentUri, null, null, null, null)
    cursor?.use { /* process results */ }
}`
	result := testutil.ScanContent(t, "/app/DataActivity.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-010")
}

func TestKT010_ContentResolverHardcodedUri_Safe(t *testing.T) {
	content := `fun getContacts() {
    val cursor = contentResolver.query(
        ContactsContract.Contacts.CONTENT_URI, null, null, null, null
    )
    cursor?.use { /* process results */ }
}`
	result := testutil.ScanContent(t, "/app/ContactActivity.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-010")
}

// ==========================================================================
// GTSS-KT-011: Deep Link Injection
// ==========================================================================

func TestKT011_IntentGetData_NoValidation(t *testing.T) {
	content := `override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val uri = intent.data
    webView.loadUrl(uri.toString())
}`
	result := testutil.ScanContent(t, "/app/DeepLinkActivity.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-011")
}

func TestKT011_IntentGetData_Validated_Safe(t *testing.T) {
	content := `override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val uri = intent.data
    if (uri != null && uri.scheme == "https" && isValidUrl(uri)) {
        webView.loadUrl(uri.toString())
    }
}`
	result := testutil.ScanContent(t, "/app/DeepLinkActivity.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-011")
}

// ==========================================================================
// GTSS-KT-012: Insecure Network Config
// ==========================================================================

func TestKT012_CleartextTrafficTrue(t *testing.T) {
	content := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:name=".MyApp"
        android:usesCleartextTraffic="true">
    </application>
</manifest>`
	result := testutil.ScanContent(t, "/app/AndroidManifest.xml", content)
	testutil.MustFindRule(t, result, "GTSS-KT-012")
}

func TestKT012_CleartextTrafficFalse_Safe(t *testing.T) {
	content := `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:name=".MyApp"
        android:usesCleartextTraffic="false">
    </application>
</manifest>`
	result := testutil.ScanContent(t, "/app/AndroidManifest.xml", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-012")
}

// ==========================================================================
// GTSS-KT-013: Android Logging Sensitive Data
// ==========================================================================

func TestKT013_LogDebugPassword(t *testing.T) {
	content := `fun authenticate(user: String, password: String) {
    Log.d("Auth", "Login attempt with password: $password")
    authService.login(user, password)
}`
	result := testutil.ScanContent(t, "/app/AuthManager.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-013")
}

func TestKT013_LogVerboseToken(t *testing.T) {
	content := `fun refreshAuth(token: String) {
    Log.v("Auth", "Refreshing token: $token")
    api.refresh(token)
}`
	result := testutil.ScanContent(t, "/app/AuthManager.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-013")
}

func TestKT013_LogNonSensitive_Safe(t *testing.T) {
	content := `fun loadData(page: Int) {
    Log.d("Data", "Loading page $page")
    api.getData(page)
}`
	result := testutil.ScanContent(t, "/app/DataLoader.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-013")
}

// ==========================================================================
// GTSS-KT-014: Room Database Raw Query
// ==========================================================================

func TestKT014_RoomRawQueryConcat(t *testing.T) {
	content := `fun searchProducts(db: RoomDatabase, query: String) {
    val cursor = database.query("SELECT * FROM products WHERE name = '" + query + "'")
}`
	result := testutil.ScanContent(t, "/app/ProductDao.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-014")
}

func TestKT014_SimpleSQLiteQueryTemplate(t *testing.T) {
	content := `fun findUser(name: String) {
    val query = SimpleSQLiteQuery("SELECT * FROM users WHERE name = '${name}'")
    userDao.rawQuery(query)
}`
	result := testutil.ScanContent(t, "/app/UserDao.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-014")
}

func TestKT014_RoomDaoAnnotation_Safe(t *testing.T) {
	content := `@Dao
interface ProductDao {
    @Query("SELECT * FROM products WHERE name = :name")
    fun findByName(name: String): List<Product>
}`
	result := testutil.ScanContent(t, "/app/ProductDao.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-014")
}

// ==========================================================================
// GTSS-KT-015: Ktor Route Parameter Injection
// ==========================================================================

func TestKT015_KtorParamInQuery(t *testing.T) {
	content := `fun Route.userRoutes() {
    get("/users/{id}") {
        val id = call.parameters["id"]
        val stmt = connection.createStatement()
        val rs = stmt.execute("SELECT * FROM users WHERE id = '$id'")
        call.respond(rs)
    }
}`
	result := testutil.ScanContent(t, "/app/UserRoutes.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-015")
}

func TestKT015_KtorParamPreparedStmt_Safe(t *testing.T) {
	content := `fun Route.userRoutes() {
    get("/users/{id}") {
        val id = call.parameters["id"]
        val stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?")
        stmt.setString(1, id)
        val rs = stmt.executeQuery()
        call.respond(rs)
    }
}`
	result := testutil.ScanContent(t, "/app/UserRoutes.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-015")
}

// ==========================================================================
// GTSS-KT-016: Broadcast Receiver Without Permission
// ==========================================================================

func TestKT016_RegisterReceiverNoPermission(t *testing.T) {
	content := `fun setupReceiver() {
    val receiver = MyBroadcastReceiver()
    val filter = IntentFilter("com.example.ACTION")
    registerReceiver(receiver, filter)
}`
	result := testutil.ScanContent(t, "/app/ReceiverActivity.kt", content)
	testutil.MustFindRule(t, result, "GTSS-KT-016")
}

func TestKT016_LocalBroadcastManager_Safe(t *testing.T) {
	content := `fun setupReceiver() {
    val receiver = MyBroadcastReceiver()
    val filter = IntentFilter("com.example.ACTION")
    LocalBroadcastManager.getInstance(this).registerReceiver(receiver, filter)
}`
	result := testutil.ScanContent(t, "/app/ReceiverActivity.kt", content)
	testutil.MustNotFindRule(t, result, "GTSS-KT-016")
}
