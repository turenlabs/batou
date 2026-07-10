using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class XssController : Controller
    {
        [HttpGet]
        public IActionResult Greet()
        {
            string name = Request.Query["name"];
            ViewBag.Name = name;
            return View(); // View uses @Html.Raw(ViewBag.Name)
        }
    }

    // Razor view:
    public class GreetView
    {
        public string Render(dynamic ViewBag) =>
            Html.Raw(ViewBag.Name).ToString();
    }
}
