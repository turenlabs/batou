using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiController : Controller
    {
        [HttpGet]
        public IActionResult Lookup()
        {
            string domain = Request.Query["domain"];
            var psi = new ProcessStartInfo("nslookup", domain);
            psi.RedirectStandardOutput = true;
            Process.Start(psi);
            return Ok();
        }
    }
}
