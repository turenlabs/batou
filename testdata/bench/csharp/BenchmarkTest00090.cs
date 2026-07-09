using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SsrfController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Health()
        {
            string service = Request.Query["service"];
            string url = "http://" + service + ":8080/health";
            var response = await _client.GetAsync(url);
            return Ok(response.StatusCode);
        }
    }
}
