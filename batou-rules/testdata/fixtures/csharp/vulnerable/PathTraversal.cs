using System;
using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class FilesController : ControllerBase
    {
        // Vulnerable: user input in File.ReadAllText path
        [HttpGet("read")]
        public IActionResult ReadFile(string filename)
        {
            var path = Path.Combine("/var/data/uploads", filename);
            var content = File.ReadAllText(path);
            return Ok(content);
        }

        // Vulnerable: user input in file write path
        [HttpPost("write")]
        public IActionResult WriteFile(string filename, string content)
        {
            var path = "/var/data/uploads/" + filename;
            File.WriteAllText(path, content);
            return Ok();
        }

        // Vulnerable: user input in file deletion
        [HttpDelete("delete")]
        public IActionResult DeleteFile(string filename)
        {
            File.Delete("/var/data/uploads/" + filename);
            return Ok();
        }
    }
}
