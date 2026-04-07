using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Threading.Tasks;

namespace Vulnerable.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ProxyController : ControllerBase
    {
        private readonly HttpClient _httpClient;

        public ProxyController(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        [HttpGet("fetch")]
        public async Task<IActionResult> Fetch([FromQuery] string url)
        {
            // Vulnerable: user-controlled URL passed directly to HttpClient
            var response = await _httpClient.GetStringAsync(url);
            return Content(response);
        }
    }
}
