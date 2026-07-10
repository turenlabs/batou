using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathController : Controller
    {
        [HttpPost]
        public IActionResult Upload()
        {
            string dir = Request.Form["dir"];
            string name = Request.Form["name"];
            string fullPath = Path.Combine("/uploads", dir, name);
            File.WriteAllText(fullPath, "content");
            return Ok();
        }
    }
}
