using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SsrfController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Rss()
        {
            string feedUrl = Request.Query["feed"];
            var xml = await _client.GetStringAsync(feedUrl);
            return Content(xml, "application/xml");
        }
    }
}
