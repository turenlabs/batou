using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathController : Controller
    {
        [HttpPost]
        public IActionResult Delete()
        {
            string filename = Request.Form["file"];
            File.Delete(Path.Combine("/uploads", filename));
            return Ok();
        }
    }
}
