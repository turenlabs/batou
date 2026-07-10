using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectController : Controller
    {
        [HttpPost]
        public IActionResult Logout()
        {
            string logoutUrl = Request.Form["logoutUrl"];
            return Redirect(logoutUrl);
        }
    }
}
