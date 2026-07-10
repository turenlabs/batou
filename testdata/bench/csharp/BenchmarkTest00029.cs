using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class XssController : Controller
    {
        [HttpGet]
        public IActionResult Image()
        {
            string alt = Request.Query["alt"];
            ViewBag.Alt = Html.Raw(alt);
            return View();
        }
    }
}
