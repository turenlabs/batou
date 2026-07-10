using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectSafeController : Controller
    {
        [HttpGet]
        public IActionResult Callback()
        {
            string returnUrl = Request.Query["returnUrl"];
            return LocalRedirect(returnUrl);
        }
    }
}
