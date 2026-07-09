using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectSafeController : Controller
    {
        [HttpGet]
        public IActionResult Next()
        {
            string path = Request.Query["path"];
            if (!path.StartsWith("/") || path.StartsWith("//")) return BadRequest();
            return Redirect(path);
        }
    }
}
