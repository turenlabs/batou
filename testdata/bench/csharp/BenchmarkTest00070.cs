using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathController : Controller
    {
        [HttpGet]
        public IActionResult Log()
        {
            string logfile = Request.Query["log"];
            var lines = File.ReadAllLines("/var/log/" + logfile);
            return Ok(string.Join("\n", lines));
        }
    }
}
