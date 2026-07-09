using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;

namespace BenchApp.Controllers
{
    public class CmdiSafeController : Controller
    {
        [HttpGet]
        public IActionResult Traceroute()
        {
            string target = Request.Query["target"];
            if (!Regex.IsMatch(target, @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"))
                return BadRequest("Invalid IP");
            var psi = new ProcessStartInfo("traceroute", target);
            psi.UseShellExecute = false;
            Process.Start(psi);
            return Ok();
        }
    }
}
