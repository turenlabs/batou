using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace BenchApp.Controllers
{
    public class CmdiSafeController : Controller
    {
        [HttpGet]
        public IActionResult Lookup()
        {
            string domain = Request.Query["domain"];
            var addresses = Dns.GetHostAddresses(domain);
            return Ok(addresses);
        }
    }
}
