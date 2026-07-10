using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectController : Controller
    {
        [HttpPost]
        public IActionResult After()
        {
            string target = Request.Form["redirect"];
            return Redirect(target);
        }
    }
}
