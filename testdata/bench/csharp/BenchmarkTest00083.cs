using System.Net;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SsrfController : Controller
    {
        [HttpGet]
        public IActionResult Download()
        {
            string url = Request.Query["url"];
            var client = new WebClient();
            string data = client.DownloadString(url);
            return Ok(data);
        }
    }
}
