using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class PathSafeController : Controller
    {
        [HttpGet]
        public IActionResult Config()
        {
            string env = Request.Query["env"];
            string safeName = Path.GetFileName(env);
            string config = File.ReadAllText(Path.Combine("/config", safeName + ".json"));
            return Ok(config);
        }
    }
}
