using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathController : Controller
    {
        [HttpGet]
        public IActionResult List()
        {
            string folder = Request.Query["folder"];
            string[] files = Directory.GetFiles("/data/" + folder);
            return Ok(files);
        }
    }
}
