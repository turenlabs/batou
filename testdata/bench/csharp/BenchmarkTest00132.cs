using Microsoft.AspNetCore.Mvc;
using System;

namespace BenchApp.Controllers
{
    public class RedirectSafeController : Controller
    {
        [HttpGet]
        public IActionResult Go()
        {
            string url = Request.Query["url"];
            var uri = new Uri(url);
            if (uri.Host != "example.com") return BadRequest();
            return Redirect(url);
        }
    }
}
