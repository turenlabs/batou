using System.IO;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

namespace BenchApp.Controllers
{
    public class PathSafeController : Controller
    {
        private static readonly HashSet<string> AllowedFiles = new() { "readme.txt", "license.txt", "help.txt" };

        [HttpGet]
        public IActionResult Static()
        {
            string name = Request.Query["name"];
            if (!AllowedFiles.Contains(name)) return NotFound();
            string content = File.ReadAllText(Path.Combine("/docs", name));
            return Ok(content);
        }
    }
}
