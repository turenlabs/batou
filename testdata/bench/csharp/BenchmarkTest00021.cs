using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class XssController : Controller
    {
        [HttpGet]
        public IActionResult Echo()
        {
            string input = Request.Query["msg"];
            ViewBag.Input = Html.Raw(input);
            return View();
        }
    }
}
