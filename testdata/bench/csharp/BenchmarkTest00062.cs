using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathController : Controller
    {
        [HttpGet]
        public IActionResult Read()
        {
            string path = Request.Query["path"];
            byte[] data = File.ReadAllBytes(path);
            return File(data, "application/octet-stream");
        }
    }
}
