using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class XssController : Controller
    {
        [HttpGet]
        public IActionResult LinkGen()
        {
            string label = Request.Query["label"];
            ViewBag.Label = Html.Raw(label);
            return View();
        }
    }
}
