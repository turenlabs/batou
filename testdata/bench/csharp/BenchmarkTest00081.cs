using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SsrfController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Fetch()
        {
            string url = Request.Query["url"];
            var response = await _client.GetAsync(url);
            var content = await response.Content.ReadAsStringAsync();
            return Ok(content);
        }
    }
}
