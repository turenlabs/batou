using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiController : Controller
    {
        [HttpPost]
        public IActionResult Convert()
        {
            string filename = Request.Form["file"];
            var psi = new ProcessStartInfo($"convert {filename} output.png");
            Process.Start(psi);
            return Ok();
        }
    }
}
