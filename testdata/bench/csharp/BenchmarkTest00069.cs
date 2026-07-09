using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathController : Controller
    {
        [HttpGet]
        public IActionResult Config()
        {
            string env = Request.Query["env"];
            string config = File.ReadAllText("/config/" + env + ".json");
            return Ok(config);
        }
    }
}
