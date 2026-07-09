using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathSafeController : Controller
    {
        [HttpGet]
        public IActionResult Image()
        {
            string name = Request.Query["img"];
            string safe = Path.GetFileName(name);
            string path = Path.Combine("/images", safe);
            if (!System.IO.File.Exists(path)) return NotFound();
            return PhysicalFile(path, "image/jpeg");
        }
    }
}
