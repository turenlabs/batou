using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathController : Controller
    {
        [HttpGet]
        public IActionResult Template()
        {
            string name = Request.Query["template"];
            string content = File.ReadAllText($"/templates/{name}.html");
            return Content(content, "text/html");
        }
    }
}
