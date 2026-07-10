using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathController : Controller
    {
        [HttpGet]
        public IActionResult Download()
        {
            string filename = Request.Query["file"];
            string content = File.ReadAllText("/var/data/" + filename);
            return Ok(content);
        }
    }
}
