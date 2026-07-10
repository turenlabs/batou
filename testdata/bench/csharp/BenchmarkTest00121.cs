using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectController : Controller
    {
        [HttpGet]
        public IActionResult Login()
        {
            string returnUrl = Request.Query["returnUrl"];
            return Redirect(returnUrl);
        }
    }
}
