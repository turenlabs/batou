using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SsrfController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Check()
        {
            string endpoint = Request.Query["endpoint"];
            var response = await _client.SendAsync(new HttpRequestMessage(HttpMethod.Head, endpoint));
            return Ok(response.StatusCode);
        }
    }
}
