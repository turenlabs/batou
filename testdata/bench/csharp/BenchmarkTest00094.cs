using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
using System;

namespace BenchApp.Controllers
{
    public class SsrfSafeController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Proxy()
        {
            string url = Request.Query["url"];
            var uri = new Uri(url);
            if (uri.Scheme != "https") return BadRequest("HTTPS only");
            if (uri.Host.EndsWith(".internal.com")) return BadRequest("Internal hosts blocked");
            if (uri.IsLoopback) return BadRequest("Loopback blocked");
            var response = await _client.GetAsync(uri);
            return Ok(await response.Content.ReadAsStringAsync());
        }
    }
}
