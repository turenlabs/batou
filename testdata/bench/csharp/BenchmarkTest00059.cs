using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiSafeController : Controller
    {
        [HttpPost]
        public IActionResult Build()
        {
            var psi = new ProcessStartInfo("dotnet", "build --configuration Release");
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            var proc = Process.Start(psi);
            return Ok();
        }
    }
}
