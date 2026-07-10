using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectSafeController : Controller
    {
        [HttpGet]
        public IActionResult Dashboard()
        {
            return RedirectToAction("Index", "Dashboard");
        }
    }
}
