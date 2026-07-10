using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectController : Controller
    {
        [HttpGet]
        public IActionResult Continue()
        {
            string url = Request.Query["continue"];
            return Redirect(url);
        }
    }
}
