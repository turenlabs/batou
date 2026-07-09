using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Hosting;

namespace BenchApp.Controllers
{
    public class PathController : Controller
    {
        private readonly IWebHostEnvironment _env;

        [HttpGet]
        public IActionResult Static()
        {
            string file = Request.Query["name"];
            string path = _env.ContentRootPath + "/wwwroot/" + file;
            return PhysicalFile(path, "application/octet-stream");
        }
    }
}
