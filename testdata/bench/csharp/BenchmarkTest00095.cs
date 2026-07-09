using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

namespace BenchApp.Controllers
{
    public class SsrfSafeController : Controller
    {
        private static readonly Dictionary<string, string> ServiceMap = new()
        {
            { "users", "https://users-svc.internal:8080" },
            { "orders", "https://orders-svc.internal:8080" },
        };
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Service()
        {
            string svc = Request.Query["service"];
            if (!ServiceMap.TryGetValue(svc, out var baseUrl)) return NotFound();
            var response = await _client.GetAsync($"{baseUrl}/health");
            return Ok(response.StatusCode);
        }
    }
}
