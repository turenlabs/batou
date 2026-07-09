using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class XssController : Controller
    {
        [HttpGet]
        public IActionResult Profile()
        {
            string bio = Request.Query["bio"];
            ViewBag.UserBio = Html.Raw(bio);
            return View();
        }
    }
}
