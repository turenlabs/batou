using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

namespace BenchApp.Controllers
{
    public class RedirectController : Controller
    {
        [HttpGet]
        public void Forward()
        {
            string dest = HttpContext.Request.Query["dest"];
            HttpContext.Response.Redirect(dest);
        }
    }
}
