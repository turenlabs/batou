using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class XssSafeController : Controller
    {
        [HttpGet]
        public IActionResult Display()
        {
            int id = int.Parse(Request.Query["id"]);
            string html = $"<p>Item #{id}</p>";
            return Content(html, "text/html");
        }
    }
}
