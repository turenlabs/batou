using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace Safe.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ProxyController : ControllerBase
    {
        private readonly HttpClient _httpClient;
        private static readonly HashSet<string> AllowedHosts = new()
        {
            "api.example.com",
            "cdn.example.com"
        };

        public ProxyController(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        [HttpGet("fetch")]
        public async Task<IActionResult> Fetch([FromQuery] string url)
        {
            // Safe: validate URL structure and check host against allowlist
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                return BadRequest("Invalid URL");
            }

            if (!AllowedHosts.Contains(uri.Host))
            {
                return BadRequest("Host not allowed");
            }

            // Safe: block internal IPs
            if (IPAddress.TryParse(uri.Host, out var ip) && IPAddress.IsLoopback(ip))
            {
                return BadRequest("Loopback addresses not allowed");
            }

            var response = await _httpClient.GetStringAsync(uri);
            return Content(response);
        }
    }
}
