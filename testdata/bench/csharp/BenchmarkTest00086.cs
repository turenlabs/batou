using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SsrfController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Image()
        {
            string imageUrl = Request.Query["src"];
            var data = await _client.GetByteArrayAsync(imageUrl);
            return File(data, "image/png");
        }
    }
}
