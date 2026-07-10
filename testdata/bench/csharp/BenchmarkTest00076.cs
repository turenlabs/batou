using System.IO;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;

namespace BenchApp.Controllers
{
    public class PathSafeController : Controller
    {
        [HttpGet]
        public IActionResult Template()
        {
            string name = Request.Query["template"];
            if (!Regex.IsMatch(name, @"^[a-zA-Z0-9_\-]+$")) return BadRequest();
            string content = File.ReadAllText($"/templates/{name}.html");
            return Content(content, "text/html");
        }
    }
}
