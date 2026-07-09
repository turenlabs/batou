using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathSafeController : Controller
    {
        [HttpGet]
        public IActionResult GetById()
        {
            int id = int.Parse(Request.Query["id"]);
            string path = Path.Combine("/data", $"{id}.json");
            string content = File.ReadAllText(path);
            return Ok(content);
        }
    }
}
