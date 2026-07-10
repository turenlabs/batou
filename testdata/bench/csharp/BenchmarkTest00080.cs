using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathSafeController : Controller
    {
        [HttpGet]
        public IActionResult List()
        {
            int page = int.Parse(Request.Query["page"]);
            string[] files = Directory.GetFiles("/data", "*.txt");
            return Ok(files);
        }
    }
}
