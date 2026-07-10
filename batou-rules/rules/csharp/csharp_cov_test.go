package csharp

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// ---------------------------------------------------------------------------
// BATOU-CS-031: TLS certificate validation bypass
// ---------------------------------------------------------------------------

func TestCS031_LambdaReturnsTrue(t *testing.T) {
	content := `using System.Net.Http;
public class Api {
    public HttpClient Build() {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;
        return new HttpClient(handler);
    }
}`
	result := testutil.ScanContent(t, "/app/Api.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-031")
}

func TestCS031_DangerousAccept(t *testing.T) {
	content := `using System.Net.Http;
public class Api {
    public void Build(HttpClientHandler handler) {
        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
    }
}`
	result := testutil.ScanContent(t, "/app/Api.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-031")
}

func TestCS031_RealValidationClean(t *testing.T) {
	// Near-miss: a real validation callback that inspects errors must NOT fire.
	content := `using System.Net.Security;
public class Api {
    public bool Validate(object s, System.Security.Cryptography.X509Certificates.X509Certificate cert,
        System.Security.Cryptography.X509Certificates.X509Chain chain, SslPolicyErrors errors) {
        return errors == SslPolicyErrors.None;
    }
}`
	result := testutil.ScanContent(t, "/app/Api.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-031")
}

// ---------------------------------------------------------------------------
// BATOU-CS-032: Weak symmetric cipher
// ---------------------------------------------------------------------------

func TestCS032_DESCryptoServiceProvider(t *testing.T) {
	content := `using System.Security.Cryptography;
public class Crypto {
    public void Encrypt() {
        var des = new DESCryptoServiceProvider();
        var enc = des.CreateEncryptor();
    }
}`
	result := testutil.ScanContent(t, "/app/Crypto.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-032")
}

func TestCS032_RijndaelManaged(t *testing.T) {
	content := `using System.Security.Cryptography;
public class Crypto {
    public void Encrypt() {
        var algo = new RijndaelManaged();
    }
}`
	result := testutil.ScanContent(t, "/app/Crypto.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-032")
}

func TestCS032_AesClean(t *testing.T) {
	content := `using System.Security.Cryptography;
public class Crypto {
    public void Encrypt() {
        using var aes = Aes.Create();
    }
}`
	result := testutil.ScanContent(t, "/app/Crypto.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-032")
}

// ---------------------------------------------------------------------------
// BATOU-CS-033: Weak hash algorithm
// ---------------------------------------------------------------------------

func TestCS033_MD5Create(t *testing.T) {
	content := `using System.Security.Cryptography;
public class Signer {
    public byte[] Sign(byte[] data) {
        using var md5 = MD5.Create();
        return md5.ComputeHash(data);
    }
}`
	result := testutil.ScanContent(t, "/app/Signer.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-033")
}

func TestCS033_SHA1Managed(t *testing.T) {
	content := `using System.Security.Cryptography;
public class Signer {
    public byte[] Sign(byte[] data) {
        var sha = new SHA1Managed();
        return sha.ComputeHash(data);
    }
}`
	result := testutil.ScanContent(t, "/app/Signer.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-033")
}

func TestCS033_SHA256Clean(t *testing.T) {
	content := `using System.Security.Cryptography;
public class Signer {
    public byte[] Sign(byte[] data) {
        using var sha = SHA256.Create();
        return sha.ComputeHash(data);
    }
}`
	result := testutil.ScanContent(t, "/app/Signer.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-033")
}

func TestCS033_NonSecurityChecksumClean(t *testing.T) {
	// Near-miss: MD5 explicitly used as a non-security content checksum.
	content := `using System.Security.Cryptography;
public class Cache {
    public string ContentHash(byte[] data) {
        // checksum only, not for security
        using var md5 = MD5.Create();
        return System.Convert.ToBase64String(md5.ComputeHash(data));
    }
}`
	result := testutil.ScanContent(t, "/app/Cache.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-033")
}

// ---------------------------------------------------------------------------
// BATOU-CS-034: JWT validation weakened
// ---------------------------------------------------------------------------

func TestCS034_RequireSignedTokensFalse(t *testing.T) {
	content := `using Microsoft.IdentityModel.Tokens;
public class Auth {
    public TokenValidationParameters Build() {
        return new TokenValidationParameters {
            RequireSignedTokens = false,
            ValidIssuer = "issuer"
        };
    }
}`
	result := testutil.ScanContent(t, "/app/Auth.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-034")
}

func TestCS034_ValidateLifetimeFalse(t *testing.T) {
	content := `using Microsoft.IdentityModel.Tokens;
public class Auth {
    public TokenValidationParameters Build() {
        return new TokenValidationParameters {
            ValidateLifetime = false
        };
    }
}`
	result := testutil.ScanContent(t, "/app/Auth.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-034")
}

func TestCS034_SecureDefaultsClean(t *testing.T) {
	content := `using Microsoft.IdentityModel.Tokens;
public class Auth {
    public TokenValidationParameters Build() {
        return new TokenValidationParameters {
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            RequireExpirationTime = true
        };
    }
}`
	result := testutil.ScanContent(t, "/app/Auth.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-034")
}

// ---------------------------------------------------------------------------
// BATOU-CS-035: CORS reflective allow-all
// ---------------------------------------------------------------------------

func TestCS035_SetIsOriginAllowedTrue(t *testing.T) {
	content := `public class Startup {
    public void Configure() {
        services.AddCors(o => o.AddPolicy("p", b =>
            b.SetIsOriginAllowed(_ => true).AllowCredentials()));
    }
}`
	result := testutil.ScanContent(t, "/app/Startup.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-035")
}

func TestCS035_OriginAllowlistClean(t *testing.T) {
	content := `public class Startup {
    public void Configure() {
        services.AddCors(o => o.AddPolicy("p", b =>
            b.SetIsOriginAllowed(origin => allowed.Contains(origin)).AllowCredentials()));
    }
}`
	result := testutil.ScanContent(t, "/app/Startup.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-035")
}

// ---------------------------------------------------------------------------
// BATOU-CS-036: Missing HSTS
// ---------------------------------------------------------------------------

func TestCS036_HttpsRedirectionNoHsts(t *testing.T) {
	content := `using Microsoft.AspNetCore.Builder;
public class Startup {
    public void Configure(IApplicationBuilder app) {
        app.UseHttpsRedirection();
        app.UseRouting();
        app.UseAuthorization();
    }
}`
	result := testutil.ScanContent(t, "/app/Startup.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-036")
}

func TestCS036_WithHstsClean(t *testing.T) {
	content := `using Microsoft.AspNetCore.Builder;
public class Startup {
    public void Configure(IApplicationBuilder app) {
        app.UseHsts();
        app.UseHttpsRedirection();
        app.UseRouting();
    }
}`
	result := testutil.ScanContent(t, "/app/Startup.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-036")
}

// ---------------------------------------------------------------------------
// BATOU-CS-037: Directory browsing
// ---------------------------------------------------------------------------

func TestCS037_UseDirectoryBrowser(t *testing.T) {
	content := `using Microsoft.AspNetCore.Builder;
public class Startup {
    public void Configure(IApplicationBuilder app) {
        app.UseDirectoryBrowser();
    }
}`
	result := testutil.ScanContent(t, "/app/Startup.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-037")
}

func TestCS037_StaticFilesClean(t *testing.T) {
	content := `using Microsoft.AspNetCore.Builder;
public class Startup {
    public void Configure(IApplicationBuilder app) {
        app.UseStaticFiles();
    }
}`
	result := testutil.ScanContent(t, "/app/Startup.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-037")
}

// ---------------------------------------------------------------------------
// BATOU-CS-038: Account lockout disabled
// ---------------------------------------------------------------------------

func TestCS038_MaxFailedZero(t *testing.T) {
	content := `using Microsoft.AspNetCore.Identity;
public class Setup {
    public void Configure() {
        services.Configure<IdentityOptions>(o => {
            o.Lockout.MaxFailedAccessAttempts = 0;
        });
    }
}`
	result := testutil.ScanContent(t, "/app/Setup.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-038")
}

func TestCS038_LockoutEnabledClean(t *testing.T) {
	content := `using Microsoft.AspNetCore.Identity;
public class Setup {
    public void Configure() {
        services.Configure<IdentityOptions>(o => {
            o.Lockout.MaxFailedAccessAttempts = 5;
            o.Lockout.AllowedForNewUsers = true;
        });
    }
}`
	result := testutil.ScanContent(t, "/app/Setup.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-038")
}

// ---------------------------------------------------------------------------
// BATOU-CS-039: Remoting TypeFilterLevel.Full
// ---------------------------------------------------------------------------

func TestCS039_TypeFilterFull(t *testing.T) {
	content := `using System.Runtime.Remoting.Channels;
public class Server {
    public void Setup() {
        var provider = new BinaryServerFormatterSinkProvider();
        provider.TypeFilterLevel = TypeFilterLevel.Full;
    }
}`
	result := testutil.ScanContent(t, "/app/Server.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-039")
}

func TestCS039_TypeFilterLowClean(t *testing.T) {
	content := `using System.Runtime.Remoting.Channels;
public class Server {
    public void Setup() {
        var provider = new BinaryServerFormatterSinkProvider();
        provider.TypeFilterLevel = TypeFilterLevel.Low;
    }
}`
	result := testutil.ScanContent(t, "/app/Server.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-039")
}

// ---------------------------------------------------------------------------
// BATOU-CS-040: HttpListener wildcard prefix
// ---------------------------------------------------------------------------

func TestCS040_WildcardPrefix(t *testing.T) {
	content := `using System.Net;
public class Listener {
    public void Start() {
        var l = new HttpListener();
        l.Prefixes.Add("http://+:8080/");
        l.Start();
    }
}`
	result := testutil.ScanContent(t, "/app/Listener.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-040")
}

func TestCS040_LocalhostClean(t *testing.T) {
	content := `using System.Net;
public class Listener {
    public void Start() {
        var l = new HttpListener();
        l.Prefixes.Add("http://localhost:8080/");
        l.Start();
    }
}`
	result := testutil.ScanContent(t, "/app/Listener.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-040")
}

// ---------------------------------------------------------------------------
// BATOU-CS-041: web.config compilation debug="true"
// ---------------------------------------------------------------------------

func TestCS041_CompilationDebug(t *testing.T) {
	content := `<configuration>
  <system.web>
    <compilation debug="true" targetFramework="4.8" />
  </system.web>
</configuration>`
	result := testutil.ScanContent(t, "/app/web.config", content)
	testutil.MustFindRule(t, result, "BATOU-CS-041")
}

func TestCS041_DebugFalseClean(t *testing.T) {
	content := `<configuration>
  <system.web>
    <compilation debug="false" targetFramework="4.8" />
  </system.web>
</configuration>`
	result := testutil.ScanContent(t, "/app/web.config", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-041")
}

// ---------------------------------------------------------------------------
// BATOU-CS-042: web.config trace localOnly="false"
// ---------------------------------------------------------------------------

func TestCS042_TraceRemote(t *testing.T) {
	content := `<configuration>
  <system.web>
    <trace enabled="true" localOnly="false" pageOutput="true" />
  </system.web>
</configuration>`
	result := testutil.ScanContent(t, "/app/web.config", content)
	testutil.MustFindRule(t, result, "BATOU-CS-042")
}

func TestCS042_TraceLocalOnlyClean(t *testing.T) {
	content := `<configuration>
  <system.web>
    <trace enabled="true" localOnly="true" />
  </system.web>
</configuration>`
	result := testutil.ScanContent(t, "/app/web.config", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-042")
}

// ---------------------------------------------------------------------------
// BATOU-CS-043: X509Certificate2 hardcoded password
// ---------------------------------------------------------------------------

func TestCS043_HardcodedPfxPassword(t *testing.T) {
	content := `using System.Security.Cryptography.X509Certificates;
public class Certs {
    public X509Certificate2 Load(byte[] raw) {
        return new X509Certificate2(raw, "P@ssw0rd123");
    }
}`
	result := testutil.ScanContent(t, "/app/Certs.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-043")
}

func TestCS043_PasswordFromConfigClean(t *testing.T) {
	content := `using System.Security.Cryptography.X509Certificates;
public class Certs {
    public X509Certificate2 Load(byte[] raw) {
        return new X509Certificate2(raw, config.GetCertPassword());
    }
}`
	result := testutil.ScanContent(t, "/app/Certs.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-043")
}

// ---------------------------------------------------------------------------
// BATOU-CS-044: X509 chain verification disabled
// ---------------------------------------------------------------------------

func TestCS044_VerificationFlagsAllFlags(t *testing.T) {
	content := `using System.Security.Cryptography.X509Certificates;
public class Validator {
    public bool Check(X509Certificate2 cert) {
        var chain = new X509Chain();
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
        return chain.Build(cert);
    }
}`
	result := testutil.ScanContent(t, "/app/Validator.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-044")
}

func TestCS044_RevocationNoCheck(t *testing.T) {
	content := `using System.Security.Cryptography.X509Certificates;
public class Validator {
    public bool Check(X509Certificate2 cert) {
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(cert);
    }
}`
	result := testutil.ScanContent(t, "/app/Validator.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-044")
}

func TestCS044_DefaultChainClean(t *testing.T) {
	content := `using System.Security.Cryptography.X509Certificates;
public class Validator {
    public bool Check(X509Certificate2 cert) {
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        if (!chain.Build(cert)) { return false; }
        return true;
    }
}`
	result := testutil.ScanContent(t, "/app/Validator.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-044")
}

// ---------------------------------------------------------------------------
// BATOU-CS-045: DataContractSerializer custom resolver
// ---------------------------------------------------------------------------

func TestCS045_CustomResolver(t *testing.T) {
	content := `using System.Runtime.Serialization;
public class Importer {
    public object Build() {
        return new DataContractSerializer(typeof(object), null, 100, false, false, new MyResolver() as DataContractResolver);
    }
}`
	result := testutil.ScanContent(t, "/app/Importer.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-045")
}

func TestCS045_FixedContractClean(t *testing.T) {
	content := `using System.Runtime.Serialization;
public class Importer {
    public object Build() {
        return new DataContractSerializer(typeof(Order));
    }
}`
	result := testutil.ScanContent(t, "/app/Importer.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-045")
}

// ---------------------------------------------------------------------------
// BATOU-CS-046: RSA PKCS#1 v1.5 padding
// ---------------------------------------------------------------------------

func TestCS046_Pkcs1Padding(t *testing.T) {
	content := `using System.Security.Cryptography;
public class Enc {
    public byte[] Encrypt(byte[] data) {
        using var rsa = RSA.Create();
        return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
    }
}`
	result := testutil.ScanContent(t, "/app/Enc.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-046")
}

func TestCS046_OaepClean(t *testing.T) {
	content := `using System.Security.Cryptography;
public class Enc {
    public byte[] Encrypt(byte[] data) {
        using var rsa = RSA.Create();
        return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }
}`
	result := testutil.ScanContent(t, "/app/Enc.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-046")
}
