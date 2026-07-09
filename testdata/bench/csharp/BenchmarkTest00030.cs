using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class XssController : Controller
    {
        [HttpGet]
        public IActionResult Table()
        {
            string data = Request.Query["cell"];
            ViewBag.Cell = Html.Raw(data);
            return View();
        }
    }
}
