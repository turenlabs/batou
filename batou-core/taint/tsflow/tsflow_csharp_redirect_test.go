package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C# Open Redirect (CWE-601) — Razor Pages, Minimal API, legacy WebForms
// =========================================================================

func TestCSharp_Redirect_ResultsRedirect_Minimal(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Http;

public class Endpoints {
    public static IResult Handle() {
        string target = Console.ReadLine();
        return Results.Redirect(target);
    }
}
`
	flows := Analyze(code, "/app/Endpoints.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for Console.ReadLine -> Results.Redirect")
	}
}

// ===========================================================================
// C# SnkRedirect (CWE-601) open-redirect sink tests — exercises the newly
// added ASP.NET Core / Razor Pages redirect APIs:
//   - RedirectPreserveMethod / RedirectPermanentPreserveMethod (307/308)
//   - RedirectToPage / RedirectToPagePermanent / *PreserveMethod
//   - new RedirectResult(url)
//   - new RedirectToActionResult / RedirectToRouteResult / RedirectToPageResult
//
// Uses Console.ReadLine as the source since tsflow's C# walker recognizes it
// reliably (same pattern as TestCSharp_Redirect_NavigationManager).
// ===========================================================================

func TestCSharp_Redirect_PreserveMethod(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Mvc;

public class AuthController : Controller {
    public IActionResult Login() {
        string returnUrl = Console.ReadLine();
        return RedirectPreserveMethod(returnUrl);
    }
}
`
	flows := Analyze(code, "/app/AuthController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for Console.ReadLine -> RedirectPreserveMethod")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Redirect_TypedResultsRedirect_Minimal(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;

public class Endpoints {
    public static RedirectHttpResult Handle() {
        string target = Console.ReadLine();
        return TypedResults.Redirect(target);
    }
}
`
	flows := Analyze(code, "/app/Endpoints.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for Console.ReadLine -> TypedResults.Redirect")
	}
}
func TestCSharp_Redirect_PermanentPreserveMethod(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Mvc;

public class AuthController : Controller {
    public IActionResult Login() {
        string target = Console.ReadLine();
        return RedirectPermanentPreserveMethod(target);
    }
}
`
	flows := Analyze(code, "/app/AuthController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for Console.ReadLine -> RedirectPermanentPreserveMethod")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Redirect_RedirectToPage(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Mvc.RazorPages;

public class IndexModel : PageModel {
    public IActionResult OnGet() {
        string page = Console.ReadLine();
        return RedirectToPage(page);
    }
}
`
	flows := Analyze(code, "/app/Index.cshtml.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for Console.ReadLine -> RedirectToPage")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Redirect_RedirectToPagePermanent(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Mvc.RazorPages;

public class IndexModel : PageModel {
    public IActionResult OnGet() {
        string page = Console.ReadLine();
        return RedirectToPagePermanent(page);
    }
}
`
	flows := Analyze(code, "/app/Index.cshtml.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for Console.ReadLine -> RedirectToPagePermanent")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Redirect_NewRedirectResult(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Mvc;

public class HomeController : Controller {
    public IActionResult Go() {
        string returnUrl = Console.ReadLine();
        return new RedirectResult(returnUrl);
        string dest = Console.ReadLine();
        return new RedirectResult(dest);
    }
}
`
	flows := Analyze(code, "/app/HomeController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for Console.ReadLine -> new RedirectResult")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Redirect_ServerTransfer_Legacy(t *testing.T) {
	code := `
using System;
using System.Web;

public class LegacyPage {
    public void Page_Load(object sender, EventArgs e) {
        string target = Console.ReadLine();
        Server.Transfer(target);
    }
}
`
	flows := Analyze(code, "/app/LegacyPage.aspx.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for Console.ReadLine -> Server.Transfer")
	}
}
func TestCSharp_Redirect_NewRedirectToActionResult(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Mvc;

public class HomeController : Controller {
    public IActionResult Go() {
        string action = Console.ReadLine();
        return new RedirectToActionResult(action, "Home", null);
    }
}
`
	flows := Analyze(code, "/app/HomeController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for Console.ReadLine -> new RedirectToActionResult")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Redirect_Safe_ResultsLocalRedirect(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Http;

public class Endpoints {
    public static IResult Handle() {
        string target = Console.ReadLine();
        return Results.LocalRedirect(target);
    }
}
`
	flows := Analyze(code, "/app/Endpoints.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("Results.LocalRedirect should sanitize redirect (local-only)")
	}
}
func TestCSharp_Redirect_NewRedirectToPageResult(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Mvc;

public class HomeController : Controller {
    public IActionResult Go() {
        string page = Console.ReadLine();
        return new RedirectToPageResult(page);
    }
}
`
	flows := Analyze(code, "/app/HomeController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for Console.ReadLine -> new RedirectToPageResult")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Redirect_Safe_TypedResultsLocalRedirect(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;

public class Endpoints {
    public static RedirectHttpResult Handle() {
        string target = Console.ReadLine();
        return TypedResults.LocalRedirect(target);
    }
}
`
	flows := Analyze(code, "/app/Endpoints.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("TypedResults.LocalRedirect should sanitize redirect (local-only)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
// Safe variant — hardcoded page name should produce no redirect flow.
func TestCSharp_Redirect_RedirectToPage_HardcodedPage_Safe(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc.RazorPages;

public class IndexModel : PageModel {
    public IActionResult OnGet() {
        return RedirectToPage("/Account/Login");
    }
}
`
	flows := Analyze(code, "/app/Index.cshtml.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Errorf("unexpected redirect flow for hardcoded page name: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
