using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SsrfController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Meta()
        {
            string api = Request.Query["api"];
            string fullUrl = $"http://{api}/metadata";
            var response = await _client.GetAsync(fullUrl);
            return Ok(await response.Content.ReadAsStringAsync());
        }
    }
}
