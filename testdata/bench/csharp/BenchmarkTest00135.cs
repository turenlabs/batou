using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

namespace BenchApp.Controllers
{
    public class RedirectSafeController : Controller
    {
        private static readonly Dictionary<string, string> Routes = new()
        {
            { "home", "/" },
            { "profile", "/profile" },
            { "settings", "/settings" }
        };

        [HttpGet]
        public IActionResult Route()
        {
            string key = Request.Query["page"];
            if (!Routes.TryGetValue(key, out var url)) return NotFound();
            return Redirect(url);
        }
    }
}
