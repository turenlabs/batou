using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SsrfSafeController : Controller
    {
        private readonly HttpClient _client = new();
        private readonly string _apiBase = "https://api.example.com";

        [HttpGet]
        public async Task<IActionResult> GetUser()
        {
            int userId = int.Parse(Request.Query["id"]);
            var response = await _client.GetAsync($"{_apiBase}/users/{userId}");
            return Ok(await response.Content.ReadAsStringAsync());
        }
    }
}
