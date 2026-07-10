using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathSafeController : Controller
    {
        private const string BaseDir = "/var/data";

        [HttpGet]
        public IActionResult Download()
        {
            string filename = Request.Query["file"];
            string fullPath = Path.GetFullPath(Path.Combine(BaseDir, filename));
            if (!fullPath.StartsWith(BaseDir)) return BadRequest("Invalid path");
            string content = File.ReadAllText(fullPath);
            return Ok(content);
        }
    }
}
