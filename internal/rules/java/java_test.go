package java

import (
	"testing"

	"github.com/turen/gtss/internal/testutil"
)

// ==========================================================================
// GTSS-JAVA-001: JNDI Injection
// ==========================================================================

func TestJAVA001_JNDILookup_Concat(t *testing.T) {
	content := `import javax.naming.InitialContext;
public class JndiService {
    public Object lookup(String name) throws Exception {
        InitialContext ctx = new InitialContext();
        return ctx.lookup("ldap://server/" + name);
    }
}`
	result := testutil.ScanContent(t, "/app/JndiService.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-001")
}

func TestJAVA001_JNDILookup_Variable(t *testing.T) {
	content := `import javax.naming.InitialContext;
public class JndiService {
    public Object lookup(HttpServletRequest request) throws Exception {
        String name = request.getParameter("resource");
        InitialContext ctx = new InitialContext();
        return ctx.lookup(name);
    }
}`
	result := testutil.ScanContent(t, "/app/JndiService.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-001")
}

func TestJAVA001_JNDILookup_Static_Safe(t *testing.T) {
	content := `import javax.naming.InitialContext;
public class JndiService {
    public Object lookup() throws Exception {
        InitialContext ctx = new InitialContext();
        return ctx.lookup("java:comp/env/jdbc/mydb");
    }
}`
	result := testutil.ScanContent(t, "/app/JndiService.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-JAVA-001")
}

// ==========================================================================
// GTSS-JAVA-002: Expression Language Injection
// ==========================================================================

func TestJAVA002_ELValueExpr_Concat(t *testing.T) {
	content := `import javax.el.ExpressionFactory;
public class ELService {
    ExpressionFactory factory = ExpressionFactory.newInstance();
    public void eval(String input) {
        factory.createValueExpression(context, "${" + input + "}", String.class);
    }
}`
	result := testutil.ScanContent(t, "/app/ELService.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-002")
}

func TestJAVA002_ELValueExpr_UserInput(t *testing.T) {
	content := `import javax.el.ExpressionFactory;
public class ELController {
    ExpressionFactory factory = ExpressionFactory.newInstance();
    public void handle(HttpServletRequest request) {
        String expr = request.getParameter("expr");
        factory.createValueExpression(context, expr, String.class);
    }
}`
	result := testutil.ScanContent(t, "/app/ELController.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-002")
}

// ==========================================================================
// GTSS-JAVA-003: Spring SpEL Injection
// ==========================================================================

func TestJAVA003_SpELParseExpr_UserInput(t *testing.T) {
	content := `import org.springframework.expression.spel.standard.SpelExpressionParser;
public class SpelController {
    SpelExpressionParser parser = new SpelExpressionParser();
    public void handle(@RequestParam String input) {
        parser.parseExpression(input);
    }
}`
	result := testutil.ScanContent(t, "/app/SpelController.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-003")
}

func TestJAVA003_SpELParseExpr_Concat(t *testing.T) {
	content := `import org.springframework.expression.spel.standard.SpelExpressionParser;
public class SpelService {
    SpelExpressionParser parser = new SpelExpressionParser();
    public void handle(String input) {
        parser.parseExpression("'" + input + "'");
    }
}`
	result := testutil.ScanContent(t, "/app/SpelService.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-003")
}

func TestJAVA003_SpELParseExpr_Static_Safe(t *testing.T) {
	content := `import org.springframework.expression.spel.standard.SpelExpressionParser;
public class SpelService {
    SpelExpressionParser parser = new SpelExpressionParser();
    public void handle() {
        parser.parseExpression("'Hello World'");
    }
}`
	result := testutil.ScanContent(t, "/app/SpelService.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-JAVA-003")
}

// ==========================================================================
// GTSS-JAVA-004: Hibernate HQL Injection
// ==========================================================================

func TestJAVA004_HQLCreateQuery_Concat(t *testing.T) {
	content := `public class UserDao {
    public User findUser(Session session, String name) {
        return session.createQuery("FROM User WHERE name = '" + name + "'").uniqueResult();
    }
}`
	result := testutil.ScanContent(t, "/app/UserDao.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-004")
}

func TestJAVA004_HQLCreateQuery_Variable(t *testing.T) {
	content := `public class UserDao {
    public User findUser(Session session, String query) {
        String hql = "FROM User WHERE " + query;
        return session.createQuery(hql + " ORDER BY id").uniqueResult();
    }
}`
	result := testutil.ScanContent(t, "/app/UserDao.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-004")
}

func TestJAVA004_HQLCreateQuery_Parameterized_Safe(t *testing.T) {
	content := `public class UserDao {
    public User findUser(Session session, String name) {
        return session.createQuery("FROM User WHERE name = :name")
            .setParameter("name", name)
            .uniqueResult();
    }
}`
	result := testutil.ScanContent(t, "/app/UserDao.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-JAVA-004")
}

// ==========================================================================
// GTSS-JAVA-005: JDBC Connection String Injection
// ==========================================================================

func TestJAVA005_JDBCConnection_Concat(t *testing.T) {
	content := `public class DbService {
    public Connection connect(String host) throws Exception {
        return DriverManager.getConnection("jdbc:mysql://" + host + "/mydb");
    }
}`
	result := testutil.ScanContent(t, "/app/DbService.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-005")
}

func TestJAVA005_JDBCConnection_Static_Safe(t *testing.T) {
	content := `public class DbService {
    public Connection connect() throws Exception {
        return DriverManager.getConnection("jdbc:mysql://localhost/mydb", "user", "pass");
    }
}`
	result := testutil.ScanContent(t, "/app/DbService.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-JAVA-005")
}

// ==========================================================================
// GTSS-JAVA-006: Java RMI Deserialization
// ==========================================================================

func TestJAVA006_RMINaming_Lookup(t *testing.T) {
	content := `import java.rmi.Naming;
public class RmiClient {
    public void connect() throws Exception {
        Registry registry = LocateRegistry.getRegistry("remotehost");
        MyService service = (MyService) Naming.lookup("rmi://remotehost/service");
    }
}`
	result := testutil.ScanContent(t, "/app/RmiClient.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-006")
}

// ==========================================================================
// GTSS-JAVA-007: Insecure SSL TrustManager
// ==========================================================================

func TestJAVA007_TrustAllCerts(t *testing.T) {
	content := `import javax.net.ssl.X509TrustManager;
public class InsecureTrustManager implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
}`
	result := testutil.ScanContent(t, "/app/InsecureTrustManager.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-007")
}

func TestJAVA007_AnonymousTrustManager(t *testing.T) {
	content := `TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
};`
	result := testutil.ScanContent(t, "/app/SslConfig.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-007")
}

// ==========================================================================
// GTSS-JAVA-008: Unrestricted File Upload
// ==========================================================================

func TestJAVA008_MultipartFile_NoValidation(t *testing.T) {
	content := `@PostMapping("/upload")
public String upload(@RequestParam MultipartFile file) throws Exception {
    String filename = file.getOriginalFilename();
    file.transferTo(new File("/uploads/" + filename));
    return "ok";
}`
	result := testutil.ScanContent(t, "/app/UploadController.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-008")
}

func TestJAVA008_MultipartFile_WithValidation_Safe(t *testing.T) {
	content := `@PostMapping("/upload")
public String upload(@RequestParam MultipartFile file) throws Exception {
    String filename = file.getOriginalFilename();
    if (!filename.endsWith(".jpg") && !filename.endsWith(".png")) {
        throw new Exception("Invalid file type");
    }
    file.transferTo(new File("/uploads/" + filename));
    return "ok";
}`
	result := testutil.ScanContent(t, "/app/UploadController.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-JAVA-008")
}

// ==========================================================================
// GTSS-JAVA-009: Server-Side Template Injection
// ==========================================================================

func TestJAVA009_VelocityEvaluate_UserInput(t *testing.T) {
	content := `import org.apache.velocity.app.Velocity;
public class TemplateService {
    public void render(HttpServletRequest request) {
        String template = request.getParameter("template");
        Velocity.evaluate(context, writer, "tag", template);
    }
}`
	result := testutil.ScanContent(t, "/app/TemplateService.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-009")
}

func TestJAVA009_ThymeleafProcess_UserInput(t *testing.T) {
	content := `public class TemplateController {
    @Autowired
    TemplateEngine templateEngine;
    public String render(@RequestParam String view) {
        return templateEngine.process(view, context);
    }
}`
	result := testutil.ScanContent(t, "/app/TemplateController.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-009")
}

// ==========================================================================
// GTSS-JAVA-010: Improper Certificate Validation
// ==========================================================================

func TestJAVA010_AllowAllHostnameVerifier(t *testing.T) {
	content := `import org.apache.http.conn.ssl.SSLSocketFactory;
public class HttpConfig {
    public void configure() {
        SSLSocketFactory sf = new SSLSocketFactory(sslContext, ALLOW_ALL_HOSTNAME_VERIFIER);
    }
}`
	result := testutil.ScanContent(t, "/app/HttpConfig.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-010")
}

func TestJAVA010_NoopHostnameVerifier(t *testing.T) {
	content := `import org.apache.http.conn.ssl.NoopHostnameVerifier;
public class HttpConfig {
    public void configure() {
        HttpsURLConnection.setDefaultHostnameVerifier(NoopHostnameVerifier.INSTANCE);
    }
}`
	result := testutil.ScanContent(t, "/app/HttpConfig.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-010")
}

// ==========================================================================
// GTSS-JAVA-011: Hardcoded JDBC Credentials
// ==========================================================================

func TestJAVA011_DriverManagerInlineCredentials(t *testing.T) {
	content := `public class DbConfig {
    public Connection getConnection() throws Exception {
        return DriverManager.getConnection("jdbc:mysql://db:3306/app", "admin", "secretpass123");
    }
}`
	result := testutil.ScanContent(t, "/app/DbConfig.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-011")
}

func TestJAVA011_JDBCURLEmbeddedPassword(t *testing.T) {
	content := `public class DbConfig {
    private String url = "jdbc:mysql://db:3306/app?user=root&password=secret";
}`
	result := testutil.ScanContent(t, "/app/DbConfig.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-011")
}

func TestJAVA011_DataSourceSetPassword(t *testing.T) {
	content := `public class DbConfig {
    public DataSource dataSource() {
        HikariDataSource ds = new HikariDataSource();
        ds.setPassword("hardcoded_password");
        return ds;
    }
}`
	result := testutil.ScanContent(t, "/app/DbConfig.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-011")
}

func TestJAVA011_EnvironmentVariable_Safe(t *testing.T) {
	content := `public class DbConfig {
    public Connection getConnection() throws Exception {
        String password = System.getenv("DB_PASSWORD");
        return DriverManager.getConnection(url, user, password);
    }
}`
	result := testutil.ScanContent(t, "/app/DbConfig.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-JAVA-011")
}

// ==========================================================================
// GTSS-JAVA-012: Regex DoS
// ==========================================================================

func TestJAVA012_PatternCompile_UserInput(t *testing.T) {
	content := `public class SearchService {
    public List<String> search(HttpServletRequest request) {
        String pattern = request.getParameter("regex");
        Pattern compiled = Pattern.compile(pattern);
        return filter(compiled);
    }
}`
	result := testutil.ScanContent(t, "/app/SearchService.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-012")
}

func TestJAVA012_PatternCompile_Concat(t *testing.T) {
	content := `public class SearchService {
    public Pattern buildPattern(String input) {
        return Pattern.compile("^" + input + "$");
    }
}`
	result := testutil.ScanContent(t, "/app/SearchService.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-012")
}

func TestJAVA012_PatternCompile_Static_Safe(t *testing.T) {
	content := `public class Validator {
    private static final Pattern EMAIL = Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
}`
	result := testutil.ScanContent(t, "/app/Validator.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-JAVA-012")
}

// ==========================================================================
// GTSS-JAVA-013: Information Exposure in Error Messages
// ==========================================================================

func TestJAVA013_PrintStackTrace_ToResponse(t *testing.T) {
	content := `public class ErrorHandler {
    public void handle(HttpServletResponse response, Exception e) throws Exception {
        e.printStackTrace(response.getWriter());
    }
}`
	result := testutil.ScanContent(t, "/app/ErrorHandler.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-013")
}

func TestJAVA013_ExceptionMessage_ToResponse(t *testing.T) {
	content := `public class ErrorHandler {
    public void handle(HttpServletResponse response, Exception e) throws Exception {
        response.getWriter().write(e.getMessage());
    }
}`
	result := testutil.ScanContent(t, "/app/ErrorHandler.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-013")
}

func TestJAVA013_Logger_Safe(t *testing.T) {
	content := `public class Service {
    private static final Logger log = LoggerFactory.getLogger(Service.class);
    public void handle() {
        try {
            doWork();
        } catch (Exception e) {
            log.error("Error occurred", e);
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Service.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-JAVA-013")
}

// ==========================================================================
// GTSS-JAVA-014: Insecure Random in Security Context
// ==========================================================================

func TestJAVA014_UtilRandom_TokenGeneration(t *testing.T) {
	content := `import java.util.Random;
public class TokenService {
    private Random random = new Random();
    public String generateToken() {
        return String.valueOf(random.nextLong());
    }
}`
	result := testutil.ScanContent(t, "/app/TokenService.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-014")
}

func TestJAVA014_SecureRandom_Safe(t *testing.T) {
	content := `import java.security.SecureRandom;
public class TokenService {
    private SecureRandom random = new SecureRandom();
    public String generateToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
}`
	result := testutil.ScanContent(t, "/app/TokenService.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-JAVA-014")
}

// ==========================================================================
// GTSS-JAVA-015: Missing HttpOnly/Secure on Cookies
// ==========================================================================

func TestJAVA015_Cookie_NoFlags(t *testing.T) {
	content := `public class AuthController {
    public void login(HttpServletResponse response) {
        Cookie sessionCookie = new Cookie("session_token", token);
        response.addCookie(sessionCookie);
    }
}`
	result := testutil.ScanContent(t, "/app/AuthController.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-015")
}

func TestJAVA015_Cookie_WithFlags_Safe(t *testing.T) {
	content := `public class AuthController {
    public void login(HttpServletResponse response) {
        Cookie sessionCookie = new Cookie("session_token", token);
        sessionCookie.setHttpOnly(true);
        sessionCookie.setSecure(true);
        response.addCookie(sessionCookie);
    }
}`
	result := testutil.ScanContent(t, "/app/AuthController.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-JAVA-015")
}

// ==========================================================================
// GTSS-JAVA-016: SSRF via URL class
// ==========================================================================

func TestJAVA016_NewURL_UserInput(t *testing.T) {
	content := `public class ProxyService {
    public String fetch(@RequestParam String url) throws Exception {
        URL target = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) target.openConnection();
        return readResponse(conn);
    }
}`
	result := testutil.ScanContent(t, "/app/ProxyService.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-016")
}

func TestJAVA016_NewURL_Concat(t *testing.T) {
	content := `public class ApiClient {
    public String call(String path) throws Exception {
        URL url = new URL("https://api.internal.com/" + path);
        return readResponse(url.openConnection());
    }
}`
	result := testutil.ScanContent(t, "/app/ApiClient.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-016")
}

func TestJAVA016_NewURL_Static_Safe(t *testing.T) {
	content := `public class HealthCheck {
    public boolean check() throws Exception {
        URL url = new URL("https://api.example.com/health");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        return conn.getResponseCode() == 200;
    }
}`
	result := testutil.ScanContent(t, "/app/HealthCheck.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-JAVA-016")
}

// ==========================================================================
// GTSS-JAVA-017: Zip Slip
// ==========================================================================

func TestJAVA017_ZipEntry_NoValidation(t *testing.T) {
	content := `import java.util.zip.ZipInputStream;
public class Extractor {
    public void extract(ZipInputStream zis, File destDir) throws Exception {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File file = new File(destDir, entry.getName());
            FileOutputStream fos = new FileOutputStream(file);
            // copy data
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Extractor.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-017")
}

func TestJAVA017_ZipEntry_WithValidation_Safe(t *testing.T) {
	content := `import java.util.zip.ZipInputStream;
public class Extractor {
    public void extract(ZipInputStream zis, File destDir) throws Exception {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File file = new File(destDir, entry.getName());
            if (!file.getCanonicalPath().startsWith(destDir.getCanonicalPath())) {
                throw new SecurityException("Zip Slip detected");
            }
            FileOutputStream fos = new FileOutputStream(file);
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Extractor.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-JAVA-017")
}

// ==========================================================================
// GTSS-JAVA-018: Thread Safety Issues
// ==========================================================================

func TestJAVA018_StaticSimpleDateFormat(t *testing.T) {
	content := `public class DateUtil {
    static SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
    public static String format(Date date) {
        return sdf.format(date);
    }
}`
	result := testutil.ScanContent(t, "/app/DateUtil.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-018")
}

func TestJAVA018_SimpleDateFormat_InSpringBean(t *testing.T) {
	content := `@Service
public class DateService {
    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
    public String format(Date date) {
        return sdf.format(date);
    }
}`
	result := testutil.ScanContent(t, "/app/DateService.java", content)
	testutil.MustFindRule(t, result, "GTSS-JAVA-018")
}

func TestJAVA018_DateTimeFormatter_Safe(t *testing.T) {
	content := `import java.time.format.DateTimeFormatter;
public class DateUtil {
    static DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    public static String format(LocalDate date) {
        return date.format(formatter);
    }
}`
	result := testutil.ScanContent(t, "/app/DateUtil.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-JAVA-018")
}

func TestJAVA018_ThreadLocal_SimpleDateFormat_Safe(t *testing.T) {
	content := `public class DateUtil {
    private static ThreadLocal<SimpleDateFormat> sdf = ThreadLocal.withInitial(
        () -> new SimpleDateFormat("yyyy-MM-dd")
    );
}`
	result := testutil.ScanContent(t, "/app/DateUtil.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-JAVA-018")
}
