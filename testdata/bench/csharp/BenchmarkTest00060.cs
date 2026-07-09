using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiSafeController : Controller
    {
        [HttpGet]
        public IActionResult Health()
        {
            var psi = new ProcessStartInfo("curl", "http://localhost:8080/health");
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            var proc = Process.Start(psi);
            string result = proc.StandardOutput.ReadToEnd();
            return Ok(result);
        }
    }
}
