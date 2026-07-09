using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Net;

namespace BenchApp.Controllers
{
    public class SsrfSafeController : Controller
    {
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Fetch()
        {
            string url = Request.Query["url"];
            var uri = new Uri(url);
            var ip = Dns.GetHostAddresses(uri.Host);
            foreach (var addr in ip)
            {
                if (IPAddress.IsLoopback(addr)) return BadRequest("Blocked");
            }
            var response = await _client.GetAsync(uri);
            return Ok(await response.Content.ReadAsStringAsync());
        }
    }
}
