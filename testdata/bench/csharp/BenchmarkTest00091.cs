using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;

namespace BenchApp.Controllers
{
    public class SsrfSafeController : Controller
    {
        private static readonly HashSet<string> AllowedHosts = new() { "api.example.com", "cdn.example.com" };
        private readonly HttpClient _client = new();

        [HttpGet]
        public async Task<IActionResult> Fetch()
        {
            string url = Request.Query["url"];
            var uri = new Uri(url);
            if (!AllowedHosts.Contains(uri.Host)) return BadRequest("Host not allowed");
            var response = await _client.GetAsync(uri);
            return Ok(await response.Content.ReadAsStringAsync());
        }
    }
}
