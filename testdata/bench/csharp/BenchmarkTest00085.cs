using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SsrfController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpPost]
        public async Task<IActionResult> Webhook()
        {
            string callbackUrl = Request.Form["callback"];
            var payload = new StringContent("{\"status\":\"done\"}");
            await _client.PostAsync(callbackUrl, payload);
            return Ok();
        }
    }
}
