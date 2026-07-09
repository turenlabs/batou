using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiSafeController : Controller
    {
        [HttpGet]
        public IActionResult Status()
        {
            var psi = new System.Diagnostics.ProcessStartInfo("systemctl", "status nginx");
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            var proc = System.Diagnostics.Process.Start(psi);
            string output = proc.StandardOutput.ReadToEnd();
            return Ok(output);
        }
    }
}
