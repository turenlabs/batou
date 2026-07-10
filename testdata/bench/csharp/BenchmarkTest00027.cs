using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class XssController : Controller
    {
        [HttpGet]
        public IActionResult Tooltip()
        {
            string title = Request.Query["title"];
            ViewBag.Title = Html.Raw(title);
            return View();
        }
    }
}
