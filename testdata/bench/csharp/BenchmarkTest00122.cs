using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectController : Controller
    {
        [HttpGet]
        public IActionResult Go()
        {
            string url = Request.Query["url"];
            Response.Redirect(url);
            return new EmptyResult();
        }
    }
}
