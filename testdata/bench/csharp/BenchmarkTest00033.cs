using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class XssSafeController : Controller
    {
        [HttpGet]
        public IActionResult Profile()
        {
            string bio = Request.Query["bio"];
            ViewBag.UserBio = bio;
            return View(); // Razor auto-encodes @ViewBag.UserBio
        }
    }
}
