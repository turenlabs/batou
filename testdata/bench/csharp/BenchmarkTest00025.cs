using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class XssController : Controller
    {
        [HttpGet]
        public IActionResult Error()
        {
            string msg = Request.Query["error"];
            ViewBag.ErrorMessage = Html.Raw(msg);
            return View();
        }
    }
}
