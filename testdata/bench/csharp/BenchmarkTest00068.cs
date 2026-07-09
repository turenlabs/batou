using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathController : Controller
    {
        [HttpPost]
        public IActionResult Save()
        {
            string subdir = Request.Form["subdir"];
            string data = Request.Form["data"];
            string path = Path.Combine("/var/app/data", subdir, "output.txt");
            File.WriteAllText(path, data);
            return Ok();
        }
    }
}
