using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiController : Controller
    {
        [HttpGet]
        public IActionResult Trace()
        {
            string target = Request.Query["target"];
            var psi = new ProcessStartInfo();
            psi.FileName = "traceroute";
            psi.Arguments = target;
            Process.Start(psi);
            return Ok();
        }
    }
}
