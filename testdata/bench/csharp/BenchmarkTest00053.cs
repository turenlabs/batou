using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiSafeController : Controller
    {
        [HttpGet]
        public IActionResult Version()
        {
            var psi = new ProcessStartInfo("dotnet", "--version");
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            var proc = Process.Start(psi);
            string output = proc.StandardOutput.ReadToEnd();
            return Ok(output);
        }
    }
}
