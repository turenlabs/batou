using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SsrfSafeController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Thumbnail()
        {
            int imageId = int.Parse(Request.Query["id"]);
            var data = await _client.GetByteArrayAsync($"https://cdn.example.com/images/{imageId}/thumb.jpg");
            return File(data, "image/jpeg");
        }
    }
}
