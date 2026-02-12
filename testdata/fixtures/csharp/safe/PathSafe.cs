using System;
using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace SafeApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class FilesController : ControllerBase
    {
        private const string UploadsDir = "/var/data/uploads";

        // Safe: Path.GetFileName strips directory traversal
        [HttpGet("read")]
        public IActionResult ReadFile(string filename)
        {
            var safeName = Path.GetFileName(filename);
            var path = Path.Combine(UploadsDir, safeName);
            var fullPath = Path.GetFullPath(path);

            // Validate resolved path is within allowed directory
            if (!fullPath.StartsWith(UploadsDir))
            {
                return BadRequest("Invalid path");
            }

            var content = File.ReadAllText(fullPath);
            return Ok(content);
        }

        // Safe: integer-based file ID, no user-controlled path
        [HttpPost("write")]
        public IActionResult WriteFile(int fileId, string content)
        {
            var path = Path.Combine(UploadsDir, fileId.ToString() + ".txt");
            File.WriteAllText(path, content);
            return Ok();
        }
    }
}
