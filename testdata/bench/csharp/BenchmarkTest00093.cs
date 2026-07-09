using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SsrfSafeController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Health()
        {
            var response = await _client.GetAsync("https://api.internal.com/health");
            return Ok(response.StatusCode);
        }
    }
}
