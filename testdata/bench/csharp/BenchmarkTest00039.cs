using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class XssSafeController : Controller
    {
        [HttpGet]
        public IActionResult Report()
        {
            string data = Request.Query["value"];
            return View("Report", data); // Razor auto-encodes model in @Model
        }
    }
}
