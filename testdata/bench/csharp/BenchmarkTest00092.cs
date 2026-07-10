using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
using System;

namespace BenchApp.Controllers
{
    public class SsrfSafeController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Api()
        {
            string path = Request.Query["path"];
            string safeUrl = $"https://api.internal.com/{Uri.EscapeDataString(path)}";
            var response = await _client.GetAsync(safeUrl);
            return Ok(await response.Content.ReadAsStringAsync());
        }
    }
}
