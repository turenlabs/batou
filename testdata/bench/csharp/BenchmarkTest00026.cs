using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class XssController : Controller
    {
        [HttpGet]
        public IActionResult Search()
        {
            string query = Request.Query["q"];
            ViewBag.Query = query;
            return View(); // View: <p>Results for: @Html.Raw(ViewBag.Query)</p>
        }
    }

    public class SearchView
    {
        public string Render(dynamic ViewBag) =>
            "<p>Results for: " + Html.Raw(ViewBag.Query) + "</p>";
    }
}
