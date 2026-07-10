using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectSafeController : Controller
    {
        [HttpGet]
        public IActionResult Login()
        {
            string returnUrl = Request.Query["returnUrl"];
            if (Url.IsLocalUrl(returnUrl))
                return Redirect(returnUrl);
            return Redirect("/");
        }
    }
}
