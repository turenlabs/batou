package framework

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// ===========================================================================
// ASP.NET rules (aspnet.go) — vulnerable + safe cases.
// All ASP.NET rules require a C# file (.cs) so testutil detects LangCSharp.
// ===========================================================================

// --- BATOU-FW-ASPNET-001: [AllowAnonymous] on sensitive endpoint ---

func TestAspnet001_AllowAnonymousSensitive(t *testing.T) {
	content := `public class AdminController : Controller
{
    [AllowAnonymous]
    public IActionResult DeleteUser(int id)
    {
        return Ok();
    }
}`
	result := testutil.ScanContent(t, "/src/AdminController.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-001")
}

func TestAspnet001_AllowAnonymousNonSensitive_Safe(t *testing.T) {
	content := `public class HomeController : Controller
{
    [AllowAnonymous]
    public IActionResult Index()
    {
        return View();
    }
}`
	result := testutil.ScanContent(t, "/src/HomeController.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-ASPNET-001")
}

func TestAspnet001_CommentLine_Safe(t *testing.T) {
	content := `// [AllowAnonymous] on the admin account endpoint was removed
public class AccountController : Controller {}`
	result := testutil.ScanContent(t, "/src/AccountController.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-ASPNET-001")
}

// --- BATOU-FW-ASPNET-002: Missing ValidateAntiForgeryToken ---

func TestAspnet002_HttpPostNoToken(t *testing.T) {
	content := `public class PaymentController : Controller
{
    [HttpPost]
    public IActionResult Charge(decimal amount)
    {
        return Ok();
    }
}`
	result := testutil.ScanContent(t, "/src/PaymentController.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-002")
}

func TestAspnet002_HttpPostWithToken_Safe(t *testing.T) {
	// The rule scans the 3 lines above [HttpPost] for the token attribute,
	// so [ValidateAntiForgeryToken] must precede [HttpPost].
	content := `public class PaymentController : Controller
{
    [ValidateAntiForgeryToken]
    [HttpPost]
    public IActionResult Charge(decimal amount)
    {
        return Ok();
    }
}`
	result := testutil.ScanContent(t, "/src/PaymentController.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-ASPNET-002")
}

func TestAspnet002_AutoAntiForgery_Safe(t *testing.T) {
	content := `[AutoValidateAntiforgeryToken]
public class OrderController : Controller
{
    [HttpPost]
    public IActionResult Submit() => Ok();
}`
	result := testutil.ScanContent(t, "/src/OrderController.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-ASPNET-002")
}

// --- BATOU-FW-ASPNET-003: Html.Raw with dynamic data ---

func TestAspnet003_HtmlRawModel(t *testing.T) {
	content := `public class ViewHelper
{
    public string Render() => Html.Raw(Model.UserBio);
}`
	result := testutil.ScanContent(t, "/src/ViewHelper.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-003")
}

func TestAspnet003_HtmlRawRequest(t *testing.T) {
	content := `var html = Html.Raw(Request.Query["bio"]);`
	result := testutil.ScanContent(t, "/src/Page.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-003")
}

// --- BATOU-FW-ASPNET-004: Connection string with hardcoded password ---

func TestAspnet004_ConnStringPassword(t *testing.T) {
	content := `var connectionString = "Server=db;Database=app;User Id=sa;Password=Sup3rSecret!;";`
	result := testutil.ScanContent(t, "/src/Startup.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-004")
}

func TestAspnet004_IntegratedSecurity_Safe(t *testing.T) {
	content := `var connectionString = "Server=db;Database=app;Integrated Security=true;";`
	result := testutil.ScanContent(t, "/src/Startup.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-ASPNET-004")
}

// --- BATOU-FW-ASPNET-005: Custom errors disabled / dev exception page ---

func TestAspnet005_CustomErrorsOff(t *testing.T) {
	content := `<configuration>
  <system.web>
    <customErrors mode="Off" />
  </system.web>
</configuration>`
	result := testutil.ScanContent(t, "/src/web.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-005")
}

func TestAspnet005_DevExceptionPageUnguarded(t *testing.T) {
	content := `public void Configure(IApplicationBuilder app)
{
    app.UseDeveloperExceptionPage();
}`
	result := testutil.ScanContent(t, "/src/Startup.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-005")
}

func TestAspnet005_DevExceptionPageGuarded_Safe(t *testing.T) {
	content := `public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }
}`
	result := testutil.ScanContent(t, "/src/Startup.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-ASPNET-005")
}

// --- BATOU-FW-ASPNET-006: ViewState MAC disabled ---

func TestAspnet006_ViewStateMacOff(t *testing.T) {
	content := `<%@ Page enableViewStateMac="false" %>`
	result := testutil.ScanContent(t, "/src/page.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-006")
}

func TestAspnet006_ViewStateEncryptionNever(t *testing.T) {
	content := `var cfg = "ViewStateEncryptionMode=Never";`
	result := testutil.ScanContent(t, "/src/Config.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-006")
}

// --- BATOU-FW-ASPNET-007: Request validation disabled ---

func TestAspnet007_ValidateRequestFalse(t *testing.T) {
	content := `<%@ Page validateRequest="false" %>`
	result := testutil.ScanContent(t, "/src/page.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-007")
}

func TestAspnet007_ValidateInputFalse(t *testing.T) {
	content := `[ValidateInput(false)]
public IActionResult Save(string html) => Ok();`
	result := testutil.ScanContent(t, "/src/EditorController.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-007")
}

// --- BATOU-FW-ASPNET-008: CORS allowing all origins ---

func TestAspnet008_AllowAnyOrigin(t *testing.T) {
	content := `services.AddCors(o => o.AddPolicy("p", b => b.AllowAnyOrigin()));`
	result := testutil.ScanContent(t, "/src/Startup.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-008")
}

func TestAspnet008_WithOriginsWildcard(t *testing.T) {
	content := `builder.WithOrigins("*");`
	result := testutil.ScanContent(t, "/src/Cors.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-008")
}

func TestAspnet008_TrustedOrigin_Safe(t *testing.T) {
	content := `builder.WithOrigins("https://trusted.example.com");`
	result := testutil.ScanContent(t, "/src/Cors.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-ASPNET-008")
}

// --- BATOU-FW-ASPNET-009: Weak password settings ---

func TestAspnet009_WeakLength(t *testing.T) {
	content := `options.Password.RequiredLength = 4;`
	result := testutil.ScanContent(t, "/src/IdentityConfig.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-009")
}

func TestAspnet009_ComplexityDisabled(t *testing.T) {
	content := `options.Password.RequireDigit = false;`
	result := testutil.ScanContent(t, "/src/IdentityConfig.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-009")
}

func TestAspnet009_StrongLength_Safe(t *testing.T) {
	content := `options.Password.RequiredLength = 12;
options.Password.RequireDigit = true;`
	result := testutil.ScanContent(t, "/src/IdentityConfig.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-ASPNET-009")
}

// --- BATOU-FW-ASPNET-010: Cookie SameSite=None ---

func TestAspnet010_SameSiteNone(t *testing.T) {
	content := `options.Cookie.SameSite = SameSiteMode.None;`
	result := testutil.ScanContent(t, "/src/CookieConfig.cs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-ASPNET-010")
}

func TestAspnet010_SameSiteStrict_Safe(t *testing.T) {
	content := `options.Cookie.SameSite = SameSiteMode.Strict;`
	result := testutil.ScanContent(t, "/src/CookieConfig.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-ASPNET-010")
}

// Note: BATOU-FW-SPRING-010 (SessionFixation) is intentionally NOT registered
// (commented out in spring.go as a low-value noise rule), so it cannot be
// exercised through the scanner — no test is written for it.

// ===========================================================================
// Phoenix (Elixir) rules (phoenix.go) — extension-gated to .ex/.exs/.heex
// ===========================================================================

// --- BATOU-FW-PHOENIX-001: raw/2 XSS ---

func TestPhoenix001_RawCall(t *testing.T) {
	content := `def render_bio(bio) do
  raw(bio)
end`
	result := testutil.ScanContent(t, "/lib/app/views/user_view.ex", content)
	testutil.MustFindRule(t, result, "BATOU-FW-PHOENIX-001")
}

func TestPhoenix001_RawPipe(t *testing.T) {
	content := `assigns.body |> raw`
	result := testutil.ScanContent(t, "/lib/app/page.heex", content)
	testutil.MustFindRule(t, result, "BATOU-FW-PHOENIX-001")
}

func TestPhoenix001_NonElixirFile_Safe(t *testing.T) {
	// raw( appears but the file is not Elixir, so the rule must not fire.
	content := `raw(userInput)`
	result := testutil.ScanContent(t, "/src/helper.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-PHOENIX-001")
}

func TestPhoenix001_CommentLine_Safe(t *testing.T) {
	content := `# raw(bio) is dangerous, do not use`
	result := testutil.ScanContent(t, "/lib/app/views/user_view.ex", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-PHOENIX-001")
}

// --- BATOU-FW-PHOENIX-002: Ecto SQL injection via interpolation ---

func TestPhoenix002_FragmentInterpolation(t *testing.T) {
	content := `from(u in User, where: fragment("name = #{name}"))`
	result := testutil.ScanContent(t, "/lib/app/queries.ex", content)
	testutil.MustFindRule(t, result, "BATOU-FW-PHOENIX-002")
}

func TestPhoenix002_RepoQueryInterpolation(t *testing.T) {
	content := `Repo.query("SELECT * FROM users WHERE id = #{id}")`
	result := testutil.ScanContent(t, "/lib/app/repo_helper.ex", content)
	testutil.MustFindRule(t, result, "BATOU-FW-PHOENIX-002")
}

func TestPhoenix002_AdaptersSQLInterpolation(t *testing.T) {
	content := `Ecto.Adapters.SQL.query!(Repo, "SELECT * FROM t WHERE x = #{x}")`
	result := testutil.ScanContent(t, "/lib/app/raw.ex", content)
	testutil.MustFindRule(t, result, "BATOU-FW-PHOENIX-002")
}

func TestPhoenix002_ParameterizedFragment_Safe(t *testing.T) {
	content := `from(u in User, where: fragment("name = ?", ^name))`
	result := testutil.ScanContent(t, "/lib/app/queries.ex", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-PHOENIX-002")
}

// --- BATOU-FW-PHOENIX-003: CSRF disabled ---

func TestPhoenix003_CSRFDisabled(t *testing.T) {
	content := `plug :protect_from_forgery, with: false`
	result := testutil.ScanContent(t, "/lib/app_web/router.ex", content)
	testutil.MustFindRule(t, result, "BATOU-FW-PHOENIX-003")
}

func TestPhoenix003_DeleteCSRFToken(t *testing.T) {
	content := `conn = delete_csrf_token(conn)`
	result := testutil.ScanContent(t, "/lib/app_web/auth.ex", content)
	testutil.MustFindRule(t, result, "BATOU-FW-PHOENIX-003")
}

// --- BATOU-FW-PHOENIX-004: hardcoded secret_key_base ---

func TestPhoenix004_HardcodedSecret(t *testing.T) {
	content := `config :app, AppWeb.Endpoint,
  secret_key_base: "aB3xYz9KQm1pLwVtRnEd7sUgHcFjOiZqWePoNbMvXuTyRqAsDfGh"`
	result := testutil.ScanContent(t, "/config/prod.exs", content)
	testutil.MustFindRule(t, result, "BATOU-FW-PHOENIX-004")
}

func TestPhoenix004_EnvSecret_Safe(t *testing.T) {
	content := `secret_key_base: System.get_env("SECRET_KEY_BASE")`
	result := testutil.ScanContent(t, "/config/runtime.exs", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-PHOENIX-004")
}

// --- BATOU-FW-PHOENIX-005: LiveView handle_event without authorization ---

func TestPhoenix005_HandleEventNoAuth(t *testing.T) {
	content := `defmodule AppWeb.PageLive do
  def handle_event("delete", %{"id" => id}, socket) do
    {:noreply, socket}
  end
end`
	result := testutil.ScanContent(t, "/lib/app_web/live/page_live.ex", content)
	testutil.MustFindRule(t, result, "BATOU-FW-PHOENIX-005")
}

func TestPhoenix005_HandleEventWithCurrentUser_Safe(t *testing.T) {
	content := `defmodule AppWeb.PageLive do
  def handle_event("delete", %{"id" => id}, socket) do
    user = socket.assigns.current_user
    {:noreply, socket}
  end
end`
	result := testutil.ScanContent(t, "/lib/app_web/live/page_live.ex", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-PHOENIX-005")
}

// --- BATOU-FW-PHOENIX-006: Router pipeline without auth ---

func TestPhoenix006_BrowserPipelineNoAuth(t *testing.T) {
	content := `defmodule AppWeb.Router do
  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
  end
end`
	result := testutil.ScanContent(t, "/lib/app_web/router.ex", content)
	testutil.MustFindRule(t, result, "BATOU-FW-PHOENIX-006")
}

func TestPhoenix006_PipelineWithAuth_Safe(t *testing.T) {
	content := `defmodule AppWeb.Router do
  pipeline :browser do
    plug :accepts, ["html"]
    plug :require_auth
  end
end`
	result := testutil.ScanContent(t, "/lib/app_web/router.ex", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-PHOENIX-006")
}

func TestPhoenix006_NonRouterFile_Safe(t *testing.T) {
	// Pipeline appears, but the file path does not contain "router".
	content := `pipeline :browser do
  plug :accepts, ["html"]
end`
	result := testutil.ScanContent(t, "/lib/app_web/endpoint.ex", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-PHOENIX-006")
}
