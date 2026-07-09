using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;

namespace BenchApp.Controllers
{
    public class CmdiSafeController : Controller
    {
        [HttpGet]
        public IActionResult Ping()
        {
            string host = Request.Query["host"];
            if (!Regex.IsMatch(host, @"^[a-zA-Z0-9.\-]+$")) return BadRequest();
            var psi = new ProcessStartInfo("ping", host);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            Process.Start(psi);
            return Ok();
        }
    }
}
