using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
using System;

namespace BenchApp.Controllers
{
    public class SsrfSafeController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Avatar()
        {
            string url = Request.Query["avatar"];
            var uri = new Uri(url);
            if (!uri.Host.EndsWith(".gravatar.com")) return BadRequest();
            var data = await _client.GetByteArrayAsync(uri);
            return File(data, "image/png");
        }
    }
}
