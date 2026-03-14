package csharp

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// ---------------------------------------------------------------------------
// BATOU-CS-031: BinaryFormatter Usage
// ---------------------------------------------------------------------------

func TestCS031_Vulnerable(t *testing.T) {
	content := `using System.Runtime.Serialization.Formatters.Binary;
public class CacheService {
    public object Deserialize(byte[] data) {
        using var ms = new MemoryStream(data);
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(ms);
    }
}`
	result := testutil.ScanContent(t, "/app/CacheService.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-031")
}

func TestCS031_Safe(t *testing.T) {
	content := `using System.Text.Json;
public class CacheService {
    public T Deserialize<T>(byte[] data) {
        return JsonSerializer.Deserialize<T>(data);
    }
}`
	result := testutil.ScanContent(t, "/app/CacheService.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-031")
}

// ---------------------------------------------------------------------------
// BATOU-CS-032: JSON.NET TypeNameHandling Unsafe
// ---------------------------------------------------------------------------

func TestCS032_TypeNameHandlingAll(t *testing.T) {
	content := `using Newtonsoft.Json;
public class MessageBroker {
    public void Configure() {
        var settings = new JsonSerializerSettings {
            TypeNameHandling = TypeNameHandling.All
        };
        JsonConvert.DeserializeObject<Message>(payload, settings);
    }
}`
	result := testutil.ScanContent(t, "/app/MessageBroker.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-032")
}

func TestCS032_TypeNameHandlingAuto(t *testing.T) {
	content := `using Newtonsoft.Json;
public class EventStore {
    private readonly JsonSerializerSettings _settings = new JsonSerializerSettings {
        TypeNameHandling = TypeNameHandling.Auto
    };
}`
	result := testutil.ScanContent(t, "/app/EventStore.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-032")
}

func TestCS032_TypeNameHandlingObjects(t *testing.T) {
	content := `using Newtonsoft.Json;
public class Serializer {
    public string Serialize(object obj) {
        var settings = new JsonSerializerSettings {
            TypeNameHandling = TypeNameHandling.Objects
        };
        return JsonConvert.SerializeObject(obj, settings);
    }
}`
	result := testutil.ScanContent(t, "/app/Serializer.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-032")
}

func TestCS032_TypeNameHandlingNone_Safe(t *testing.T) {
	content := `using Newtonsoft.Json;
public class MessageBroker {
    public void Configure() {
        var settings = new JsonSerializerSettings {
            TypeNameHandling = TypeNameHandling.None
        };
        JsonConvert.DeserializeObject<Message>(payload, settings);
    }
}`
	result := testutil.ScanContent(t, "/app/MessageBroker.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-032")
}

// ---------------------------------------------------------------------------
// BATOU-CS-033: Blazor MarkupString XSS
// ---------------------------------------------------------------------------

func TestCS033_MarkupStringWithUserInput(t *testing.T) {
	content := `@code {
    [Parameter] public string userInput { get; set; }

    private MarkupString GetContent() {
        return new MarkupString(userInput);
    }
}`
	result := testutil.ScanContent(t, "/app/Component.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-033")
}

func TestCS033_MarkupStringWithQueryParam(t *testing.T) {
	content := `using Microsoft.AspNetCore.Components;
public class SearchResult : ComponentBase {
    [Parameter] public string query { get; set; }

    protected MarkupString highlighted;

    protected override void OnInitialized() {
        highlighted = new MarkupString("<b>" + query + "</b>");
    }
}`
	result := testutil.ScanContent(t, "/app/SearchResult.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-033")
}

func TestCS033_MarkupStringStaticContent_Safe(t *testing.T) {
	content := `using Microsoft.AspNetCore.Components;
public class Footer : ComponentBase {
    private MarkupString copyright = new MarkupString("<p>Copyright 2024</p>");
}`
	result := testutil.ScanContent(t, "/app/Footer.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-033")
}

// ---------------------------------------------------------------------------
// BATOU-CS-034: EF Core FromSqlRaw Injection
// ---------------------------------------------------------------------------

func TestCS034_FromSqlRawInterpolation(t *testing.T) {
	content := `using Microsoft.EntityFrameworkCore;
public class ProductRepository {
    public List<Product> Search(string name) {
        return _context.Products
            .FromSqlRaw($"SELECT * FROM Products WHERE Name = '{name}'")
            .ToList();
    }
}`
	result := testutil.ScanContent(t, "/app/ProductRepository.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-034")
}

func TestCS034_FromSqlRawConcatenation(t *testing.T) {
	content := `using Microsoft.EntityFrameworkCore;
public class OrderRepository {
    public List<Order> GetByStatus(string status) {
        var sql = "SELECT * FROM Orders WHERE Status = '" + status + "'";
        return _context.Orders.FromSqlRaw("SELECT * FROM Orders WHERE Status = '" + status).ToList();
    }
}`
	result := testutil.ScanContent(t, "/app/OrderRepository.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-034")
}

func TestCS034_FromSqlInterpolated_Safe(t *testing.T) {
	content := `using Microsoft.EntityFrameworkCore;
public class ProductRepository {
    public List<Product> Search(string name) {
        return _context.Products
            .FromSqlInterpolated($"SELECT * FROM Products WHERE Name = {name}")
            .ToList();
    }
}`
	result := testutil.ScanContent(t, "/app/ProductRepository.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-034")
}

func TestCS034_FromSqlRawParameterized_Safe(t *testing.T) {
	content := `using Microsoft.EntityFrameworkCore;
public class ProductRepository {
    public List<Product> Search(string name) {
        return _context.Products
            .FromSqlRaw("SELECT * FROM Products WHERE Name = {0}", new SqlParameter("@name", name))
            .ToList();
    }
}`
	result := testutil.ScanContent(t, "/app/ProductRepository.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-034")
}

// ---------------------------------------------------------------------------
// BATOU-CS-035: Minimal API Missing Auth
// ---------------------------------------------------------------------------

func TestCS035_MapGetNoAuth(t *testing.T) {
	content := `var app = builder.Build();
app.MapGet("/api/admin/users", async (UserService svc) => {
    return await svc.GetAllUsers();
});
app.Run();`
	result := testutil.ScanContent(t, "/app/Program.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-035")
}

func TestCS035_MapPostNoAuth(t *testing.T) {
	content := `var app = builder.Build();
app.MapPost("/api/orders", async (Order order, OrderService svc) => {
    return await svc.CreateOrder(order);
});
app.Run();`
	result := testutil.ScanContent(t, "/app/Program.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-035")
}

func TestCS035_MapGetWithRequireAuth_Safe(t *testing.T) {
	content := `var app = builder.Build();
app.MapGet("/api/admin/users", async (UserService svc) => {
    return await svc.GetAllUsers();
}).RequireAuthorization();
app.Run();`
	result := testutil.ScanContent(t, "/app/Program.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-035")
}

func TestCS035_MapGetWithAllowAnonymous_Safe(t *testing.T) {
	content := `var app = builder.Build();
app.MapGet("/api/health", () => Results.Ok("healthy"))
    .AllowAnonymous();
app.Run();`
	result := testutil.ScanContent(t, "/app/Program.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-035")
}

// ---------------------------------------------------------------------------
// BATOU-CS-036: gRPC Channel Without TLS
// ---------------------------------------------------------------------------

func TestCS036_GrpcHttpPlaintext(t *testing.T) {
	content := `using Grpc.Net.Client;
public class GrpcService {
    public void Connect() {
        var channel = GrpcChannel.ForAddress("http://grpc-server:5000");
        var client = new Greeter.GreeterClient(channel);
    }
}`
	result := testutil.ScanContent(t, "/app/GrpcService.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-036")
}

func TestCS036_GrpcHttps_Safe(t *testing.T) {
	content := `using Grpc.Net.Client;
public class GrpcService {
    public void Connect() {
        var channel = GrpcChannel.ForAddress("https://grpc-server:5001");
        var client = new Greeter.GreeterClient(channel);
    }
}`
	result := testutil.ScanContent(t, "/app/GrpcService.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-036")
}

// ---------------------------------------------------------------------------
// BATOU-CS-037: Missing Anti-Forgery Token
// ---------------------------------------------------------------------------

func TestCS037_HttpPostNoAntiForgery(t *testing.T) {
	content := `using Microsoft.AspNetCore.Mvc;
public class AccountController : Controller {
    [HttpPost]
    public IActionResult UpdateProfile(ProfileModel model) {
        _profileService.Update(model);
        return RedirectToAction("Index");
    }
}`
	result := testutil.ScanContent(t, "/app/AccountController.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-037")
}

func TestCS037_HttpDeleteNoAntiForgery(t *testing.T) {
	content := `using Microsoft.AspNetCore.Mvc;
public class ItemController : Controller {
    [HttpDelete]
    public IActionResult Remove(int id) {
        _itemService.Delete(id);
        return Ok();
    }
}`
	result := testutil.ScanContent(t, "/app/ItemController.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-037")
}

func TestCS037_HttpPostWithValidateAntiForgery_Safe(t *testing.T) {
	content := `using Microsoft.AspNetCore.Mvc;
public class AccountController : Controller {
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult UpdateProfile(ProfileModel model) {
        _profileService.Update(model);
        return RedirectToAction("Index");
    }
}`
	result := testutil.ScanContent(t, "/app/AccountController.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-037")
}

func TestCS037_HttpPostWithAutoValidate_Safe(t *testing.T) {
	content := `using Microsoft.AspNetCore.Mvc;
[AutoValidateAntiforgeryToken]
public class AccountController : Controller {
    [HttpPost]
    public IActionResult UpdateProfile(ProfileModel model) {
        _profileService.Update(model);
        return RedirectToAction("Index");
    }
}`
	result := testutil.ScanContent(t, "/app/AccountController.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-037")
}

// ---------------------------------------------------------------------------
// BATOU-CS-038: Regex Without Timeout
// ---------------------------------------------------------------------------

func TestCS038_RegexNoTimeout(t *testing.T) {
	content := `using System.Text.RegularExpressions;
public class InputValidator {
    public bool IsValidEmail(string email) {
        var regex = new Regex(@"^[\w.+-]+@[\w-]+\.[\w.]+$");
        return regex.IsMatch(email);
    }
}`
	result := testutil.ScanContent(t, "/app/InputValidator.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-038")
}

func TestCS038_RegexWithTimeSpan_Safe(t *testing.T) {
	content := `using System.Text.RegularExpressions;
public class InputValidator {
    public bool IsValidEmail(string email) {
        var regex = new Regex(@"^[\w.+-]+@[\w-]+\.[\w.]+$", RegexOptions.None, TimeSpan.FromSeconds(2));
        return regex.IsMatch(email);
    }
}`
	result := testutil.ScanContent(t, "/app/InputValidator.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-038")
}

func TestCS038_RegexWithMatchTimeout_Safe(t *testing.T) {
	content := `using System.Text.RegularExpressions;
public class InputValidator {
    public bool IsValid(string input) {
        var regex = new Regex(pattern, RegexOptions.Compiled);
        regex.MatchTimeout = TimeSpan.FromSeconds(1);
        return regex.IsMatch(input);
    }
}`
	result := testutil.ScanContent(t, "/app/InputValidator.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-038")
}

// ---------------------------------------------------------------------------
// BATOU-CS-039: Developer Exception Page in Production
// ---------------------------------------------------------------------------

func TestCS039_DevExPageNoGuard(t *testing.T) {
	content := `using Microsoft.AspNetCore.Builder;
public class Startup {
    public void Configure(IApplicationBuilder app) {
        app.UseDeveloperExceptionPage();
        app.UseRouting();
        app.UseEndpoints(endpoints => {
            endpoints.MapControllers();
        });
    }
}`
	result := testutil.ScanContent(t, "/app/Startup.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-039")
}

func TestCS039_DevExPageWithIsDevelopment_Safe(t *testing.T) {
	content := `using Microsoft.AspNetCore.Builder;
public class Startup {
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
        if (env.IsDevelopment()) {
            app.UseDeveloperExceptionPage();
        } else {
            app.UseExceptionHandler("/Error");
        }
        app.UseRouting();
    }
}`
	result := testutil.ScanContent(t, "/app/Startup.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-039")
}

func TestCS039_DevExPageWithDebugDirective_Safe(t *testing.T) {
	content := `using Microsoft.AspNetCore.Builder;
public class Startup {
    public void Configure(IApplicationBuilder app) {
        #if DEBUG
        app.UseDeveloperExceptionPage();
        #endif
        app.UseRouting();
    }
}`
	result := testutil.ScanContent(t, "/app/Startup.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-039")
}

// ---------------------------------------------------------------------------
// BATOU-CS-040: Weak Password Hashing
// ---------------------------------------------------------------------------

func TestCS040_MD5ForPassword(t *testing.T) {
	content := `using System.Security.Cryptography;
public class AuthService {
    public string HashPassword(string password) {
        using var md5 = MD5.Create();
        var bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(bytes);
    }
}`
	result := testutil.ScanContent(t, "/app/AuthService.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-040")
}

func TestCS040_SHA1ForPassword(t *testing.T) {
	content := `using System.Security.Cryptography;
public class UserService {
    public string HashPassword(string pwd) {
        using var sha1 = SHA1.Create();
        var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(pwd));
        return BitConverter.ToString(hash);
    }
}`
	result := testutil.ScanContent(t, "/app/UserService.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-040")
}

func TestCS040_SHA256ForPassword(t *testing.T) {
	content := `using System.Security.Cryptography;
public class CredentialManager {
    public byte[] HashCredential(string password) {
        using var sha = SHA256.Create();
        return sha.ComputeHash(Encoding.UTF8.GetBytes(password));
    }
}`
	result := testutil.ScanContent(t, "/app/CredentialManager.cs", content)
	testutil.MustFindRule(t, result, "BATOU-CS-040")
}

func TestCS040_PBKDF2_Safe(t *testing.T) {
	content := `using System.Security.Cryptography;
public class AuthService {
    public string HashPassword(string password) {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        var hash = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
        return Convert.ToBase64String(hash.GetBytes(32));
    }
}`
	result := testutil.ScanContent(t, "/app/AuthService.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-040")
}

func TestCS040_MD5NoPasswordContext_Safe(t *testing.T) {
	content := `using System.Security.Cryptography;
public class ChecksumService {
    public string ComputeChecksum(byte[] fileData) {
        using var md5 = MD5.Create();
        var hash = md5.ComputeHash(fileData);
        return BitConverter.ToString(hash);
    }
}`
	result := testutil.ScanContent(t, "/app/ChecksumService.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-CS-040")
}
