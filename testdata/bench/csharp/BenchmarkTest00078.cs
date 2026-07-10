using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathSafeController : Controller
    {
        private const string LogDir = "/var/log/app";

        [HttpGet]
        public IActionResult Log()
        {
            string logfile = Request.Query["log"];
            string fullPath = Path.GetFullPath(Path.Combine(LogDir, logfile));
            if (!fullPath.StartsWith(LogDir)) return Forbid();
            var lines = File.ReadAllLines(fullPath);
            return Ok(string.Join("\n", lines));
        }
    }
}
