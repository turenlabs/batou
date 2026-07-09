using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;

namespace BenchApp.Controllers
{
    public class RedirectSafeController : Controller
    {
        private static readonly HashSet<string> AllowedDomains = new() { "example.com", "app.example.com" };

        [HttpGet]
        public IActionResult External()
        {
            string url = Request.Query["url"];
            var uri = new Uri(url);
            if (!AllowedDomains.Contains(uri.Host)) return BadRequest("Domain not allowed");
            return Redirect(url);
        }
    }
}
