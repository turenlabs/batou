using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SsrfSafeController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Weather()
        {
            string city = Request.Query["city"];
            string safeCity = System.Uri.EscapeDataString(city);
            var response = await _client.GetAsync($"https://weather-api.example.com/v1/{safeCity}");
            return Ok(await response.Content.ReadAsStringAsync());
        }
    }
}
