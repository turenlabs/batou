package java

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// ==========================================================================
// BATOU-JAVA-032: AccessController.doPrivileged wrapping a dynamic op (CWE-250)
// ==========================================================================

func TestJAVA032_DoPrivileged_DynamicExec(t *testing.T) {
	content := `import java.security.AccessController;
import java.security.PrivilegedAction;
public class Priv {
    public void run(final String cmd) {
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            try {
                Runtime.getRuntime().exec(cmd);
            } catch (Exception e) {}
            return null;
        });
    }
}`
	result := testutil.ScanContent(t, "/app/Priv.java", content)
	testutil.MustFindRule(t, result, "BATOU-JAVA-032")
}

func TestJAVA032_DoPrivileged_DynamicFile(t *testing.T) {
	content := `import java.security.AccessController;
public class Priv {
    public void load(final String path) {
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            new FileInputStream(path + ".dat");
            return null;
        });
    }
}`
	result := testutil.ScanContent(t, "/app/Priv.java", content)
	testutil.MustFindRule(t, result, "BATOU-JAVA-032")
}

func TestJAVA032_DoPrivileged_ConstantOp_Safe(t *testing.T) {
	content := `import java.security.AccessController;
public class Priv {
    public String prop() {
        return AccessController.doPrivileged((PrivilegedAction<String>) () -> {
            return System.getProperty("user.home");
        });
    }
}`
	result := testutil.ScanContent(t, "/app/Priv.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-JAVA-032")
}

// ==========================================================================
// BATOU-JAVA-033: XSSRequestWrapper regex-blocklist sanitizer (CWE-79)
// ==========================================================================

func TestJAVA033_XSSWrapper_Blocklist(t *testing.T) {
	content := `import javax.servlet.http.HttpServletRequestWrapper;
public class XSSRequestWrapper extends HttpServletRequestWrapper {
    private String stripXSS(String value) {
        if (value != null) {
            value = value.replaceAll("<script>(.*?)</script>", "");
            value = value.replaceAll("javascript:", "");
        }
        return value;
    }
}`
	result := testutil.ScanContent(t, "/app/XSSRequestWrapper.java", content)
	testutil.MustFindRule(t, result, "BATOU-JAVA-033")
}

func TestJAVA033_OutputEncode_Safe(t *testing.T) {
	content := `import org.owasp.encoder.Encode;
public class SafeOut {
    public String render(String value) {
        return Encode.forHtml(value);
    }
}`
	result := testutil.ScanContent(t, "/app/SafeOut.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-JAVA-033")
}

// ==========================================================================
// BATOU-JAVA-034: anonymous LDAP bind (CWE-287)
// ==========================================================================

func TestJAVA034_AnonymousBind(t *testing.T) {
	content := `import javax.naming.Context;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;
public class Ldap {
    public void connect() throws Exception {
        Hashtable<String,String> env = new Hashtable<>();
        env.put(Context.PROVIDER_URL, "ldap://dir.example.com:389");
        env.put(Context.SECURITY_AUTHENTICATION, "none");
        InitialDirContext ctx = new InitialDirContext(env);
    }
}`
	result := testutil.ScanContent(t, "/app/Ldap.java", content)
	testutil.MustFindRule(t, result, "BATOU-JAVA-034")
}

func TestJAVA034_SimpleBind_Safe(t *testing.T) {
	content := `import javax.naming.Context;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;
public class Ldap {
    public void connect(String pw) throws Exception {
        Hashtable<String,String> env = new Hashtable<>();
        env.put(Context.PROVIDER_URL, "ldaps://dir.example.com:636");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "cn=svc,dc=example,dc=com");
        env.put(Context.SECURITY_CREDENTIALS, pw);
        InitialDirContext ctx = new InitialDirContext(env);
    }
}`
	result := testutil.ScanContent(t, "/app/Ldap.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-JAVA-034")
}

// ==========================================================================
// BATOU-JAVA-035: RestTemplate/WebClient cleartext http:// (CWE-319)
// ==========================================================================

func TestJAVA035_RestTemplate_Cleartext(t *testing.T) {
	content := `import org.springframework.web.client.RestTemplate;
public class Client {
    private final RestTemplate restTemplate = new RestTemplate();
    public String fetch() {
        return restTemplate.getForObject("http://api.partner.com/v1/data", String.class);
    }
}`
	result := testutil.ScanContent(t, "/app/Client.java", content)
	testutil.MustFindRule(t, result, "BATOU-JAVA-035")
}

func TestJAVA035_RestTemplate_Https_Safe(t *testing.T) {
	content := `import org.springframework.web.client.RestTemplate;
public class Client {
    private final RestTemplate restTemplate = new RestTemplate();
    public String fetch() {
        return restTemplate.getForObject("https://api.partner.com/v1/data", String.class);
    }
}`
	result := testutil.ScanContent(t, "/app/Client.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-JAVA-035")
}

func TestJAVA035_RestTemplate_Localhost_Safe(t *testing.T) {
	content := `import org.springframework.web.client.RestTemplate;
public class Client {
    private final RestTemplate restTemplate = new RestTemplate();
    public String fetch() {
        return restTemplate.getForObject("http://localhost:8080/health", String.class);
    }
}`
	result := testutil.ScanContent(t, "/app/Client.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-JAVA-035")
}

// ==========================================================================
// BATOU-JAVA-036: RESTEasy insecure client (CWE-295)
// ==========================================================================

func TestJAVA036_Resteasy_DisableTrust(t *testing.T) {
	content := `import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
public class RestClient {
    public void build() {
        ResteasyClientBuilder builder = new ResteasyClientBuilderImpl();
        builder.disableTrustManager();
        builder.build();
    }
}`
	result := testutil.ScanContent(t, "/app/RestClient.java", content)
	testutil.MustFindRule(t, result, "BATOU-JAVA-036")
}

func TestJAVA036_Resteasy_Default_Safe(t *testing.T) {
	content := `import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
public class RestClient {
    public void build() {
        ResteasyClientBuilder builder = ResteasyClientBuilder.newBuilder();
        builder.build();
    }
}`
	result := testutil.ScanContent(t, "/app/RestClient.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-JAVA-036")
}

// ==========================================================================
// BATOU-JAVA-037: Blowfish key size < 128 bits (CWE-326)
// ==========================================================================

func TestJAVA037_Blowfish_WeakKey(t *testing.T) {
	content := `import javax.crypto.KeyGenerator;
public class Keys {
    public void gen() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("Blowfish");
        kg.init(64);
    }
}`
	result := testutil.ScanContent(t, "/app/Keys.java", content)
	testutil.MustFindRule(t, result, "BATOU-JAVA-037")
}

func TestJAVA037_Blowfish_StrongKey_Safe(t *testing.T) {
	content := `import javax.crypto.KeyGenerator;
public class Keys {
    public void gen() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("Blowfish");
        kg.init(256);
    }
}`
	result := testutil.ScanContent(t, "/app/Keys.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-JAVA-037")
}

func TestJAVA037_AES_Init_Safe(t *testing.T) {
	// init(128) on a non-Blowfish keygen must not fire.
	content := `import javax.crypto.KeyGenerator;
public class Keys {
    public void gen() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
    }
}`
	result := testutil.ScanContent(t, "/app/Keys.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-JAVA-037")
}

// ==========================================================================
// BATOU-JAVA-038: AES-GCM nonce reuse (CWE-323)
// ==========================================================================

func TestJAVA038_GCM_StaticNonce(t *testing.T) {
	content := `import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
public class Crypto {
    private static final byte[] IV = new byte[12];
    public byte[] enc(byte[] data, javax.crypto.SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, IV);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(data);
    }
}`
	result := testutil.ScanContent(t, "/app/Crypto.java", content)
	testutil.MustFindRule(t, result, "BATOU-JAVA-038")
}

func TestJAVA038_GCM_RandomNonce_Safe(t *testing.T) {
	content := `import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
public class Crypto {
    public byte[] enc(byte[] data, javax.crypto.SecretKey key) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(data);
    }
}`
	result := testutil.ScanContent(t, "/app/Crypto.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-JAVA-038")
}

// ==========================================================================
// BATOU-JAVA-039: DefaultHttpClient instantiation (CWE-326)
// ==========================================================================

func TestJAVA039_DefaultHttpClient(t *testing.T) {
	content := `import org.apache.http.impl.client.DefaultHttpClient;
public class Http {
    public void call() {
        DefaultHttpClient client = new DefaultHttpClient();
        client.execute(new HttpGet("https://x"));
    }
}`
	result := testutil.ScanContent(t, "/app/Http.java", content)
	testutil.MustFindRule(t, result, "BATOU-JAVA-039")
}

func TestJAVA039_HttpClientBuilder_Safe(t *testing.T) {
	content := `import org.apache.http.impl.client.HttpClientBuilder;
public class Http {
    public void call() {
        var client = HttpClientBuilder.create().build();
    }
}`
	result := testutil.ScanContent(t, "/app/Http.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-JAVA-039")
}

// ==========================================================================
// BATOU-JAVA-040: SMTP without STARTTLS/SSL (CWE-319)
// ==========================================================================

func TestJAVA040_SMTP_NoTLS(t *testing.T) {
	content := `import javax.mail.Session;
import javax.mail.Transport;
import java.util.Properties;
public class Mailer {
    public void send(javax.mail.Message msg) throws Exception {
        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.example.com");
        Session session = Session.getInstance(props);
        Transport.send(msg);
    }
}`
	result := testutil.ScanContent(t, "/app/Mailer.java", content)
	testutil.MustFindRule(t, result, "BATOU-JAVA-040")
}

func TestJAVA040_SMTP_StartTLS_Safe(t *testing.T) {
	content := `import javax.mail.Session;
import javax.mail.Transport;
import java.util.Properties;
public class Mailer {
    public void send(javax.mail.Message msg) throws Exception {
        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.example.com");
        props.put("mail.smtp.starttls.enable", "true");
        Session session = Session.getInstance(props);
        Transport.send(msg);
    }
}`
	result := testutil.ScanContent(t, "/app/Mailer.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-JAVA-040")
}

// ==========================================================================
// BATOU-JAVA-041: LDAP SearchControls returning-object flag (CWE-90)
// ==========================================================================

func TestJAVA041_ReturningObjFlag(t *testing.T) {
	content := `import javax.naming.directory.SearchControls;
import javax.naming.directory.InitialDirContext;
public class Lookup {
    public void search(InitialDirContext ctx, String base) throws Exception {
        SearchControls controls = new SearchControls();
        controls.setReturningObjFlag(true);
        ctx.search(base, "(uid=*)", controls);
    }
}`
	result := testutil.ScanContent(t, "/app/Lookup.java", content)
	testutil.MustFindRule(t, result, "BATOU-JAVA-041")
}

func TestJAVA041_AttributesOnly_Safe(t *testing.T) {
	content := `import javax.naming.directory.SearchControls;
import javax.naming.directory.InitialDirContext;
public class Lookup {
    public void search(InitialDirContext ctx, String base) throws Exception {
        SearchControls controls = new SearchControls();
        controls.setReturningAttributes(new String[]{"cn", "mail"});
        ctx.search(base, "(uid=*)", controls);
    }
}`
	result := testutil.ScanContent(t, "/app/Lookup.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-JAVA-041")
}
