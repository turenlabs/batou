using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectController : Controller
    {
        [HttpGet]
        public IActionResult Callback()
        {
            string callback = Request.Query["callback"];
            return Redirect(callback);
        }
    }
}
