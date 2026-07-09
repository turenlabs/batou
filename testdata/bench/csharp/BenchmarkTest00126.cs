using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectController : Controller
    {
        [HttpGet]
        public IActionResult OAuth()
        {
            string state = Request.Query["state"];
            string redirectUri = Request.Query["redirect_uri"];
            return Redirect(redirectUri + "?state=" + state);
        }
    }
}
