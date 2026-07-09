using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectSafeController : Controller
    {
        [HttpGet]
        public IActionResult Language()
        {
            string lang = Request.Query["lang"];
            if (lang == "en" || lang == "fr" || lang == "de")
                return Redirect($"/{lang}/home");
            return Redirect("/en/home");
        }
    }
}
