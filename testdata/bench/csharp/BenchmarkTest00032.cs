using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace BenchApp.Controllers
{
    public class XssSafeController : Controller
    {
        [HttpGet]
        public ContentResult Greet()
        {
            string name = Request.Query["name"];
            string encoded = WebUtility.HtmlEncode(name);
            return Content($"<h1>Hello {encoded}!</h1>", "text/html");
        }
    }
}
