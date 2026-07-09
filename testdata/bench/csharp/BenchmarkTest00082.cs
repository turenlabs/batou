using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SsrfController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpPost]
        public async Task<IActionResult> Proxy()
        {
            string target = Request.Form["target"];
            var response = await _client.GetStringAsync(target);
            return Ok(response);
        }
    }
}
