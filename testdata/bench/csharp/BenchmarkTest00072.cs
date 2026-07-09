using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathSafeController : Controller
    {
        [HttpGet]
        public IActionResult Read()
        {
            string filename = Path.GetFileName(Request.Query["file"]);
            string path = Path.Combine("/uploads", filename);
            byte[] data = File.ReadAllBytes(path);
            return File(data, "application/octet-stream");
        }
    }
}
