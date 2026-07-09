using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiController : Controller
    {
        [HttpGet]
        public IActionResult Git()
        {
            string repo = Request.Query["repo"];
            var psi = new ProcessStartInfo("git", "clone " + repo);
            Process.Start(psi);
            return Ok();
        }
    }
}
