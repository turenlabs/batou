using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

namespace BenchApp.Controllers
{
    public class CmdiSafeController : Controller
    {
        private static readonly HashSet<string> AllowedTools = new() { "ls", "date", "whoami" };

        [HttpPost]
        public IActionResult Run()
        {
            string tool = Request.Form["tool"];
            if (!AllowedTools.Contains(tool)) return BadRequest();
            var psi = new ProcessStartInfo(tool);
            psi.UseShellExecute = false;
            Process.Start(psi);
            return Ok();
        }
    }
}
