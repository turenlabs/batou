using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectSafeController : Controller
    {
        [HttpGet]
        public IActionResult Profile()
        {
            int userId = int.Parse(Request.Query["id"]);
            return RedirectToAction("View", "Profile", new { id = userId });
        }
    }
}
