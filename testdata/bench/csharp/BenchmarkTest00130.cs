using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectController : Controller
    {
        [HttpGet]
        public IActionResult Shortener()
        {
            string target = Request.Query["t"];
            return RedirectPermanent(target);
        }
    }
}
