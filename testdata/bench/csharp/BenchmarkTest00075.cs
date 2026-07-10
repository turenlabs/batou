using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathSafeController : Controller
    {
        private const string UploadDir = "/uploads";

        [HttpPost]
        public IActionResult Upload()
        {
            string name = Request.Form["name"];
            string safeName = Path.GetFileName(name);
            if (string.IsNullOrEmpty(safeName)) return BadRequest();
            string fullPath = Path.Combine(UploadDir, safeName);
            string resolved = Path.GetFullPath(fullPath);
            if (!resolved.StartsWith(UploadDir)) return BadRequest();
            File.WriteAllText(resolved, "content");
            return Ok();
        }
    }
}
