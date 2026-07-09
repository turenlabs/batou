using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectController : Controller
    {
        [HttpGet]
        public IActionResult Next()
        {
            string next = Request.Query["next"];
            return RedirectPermanent(next);
        }
    }
}
