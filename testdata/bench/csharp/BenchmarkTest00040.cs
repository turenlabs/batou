using Microsoft.AspNetCore.Mvc;
using System.Web;

namespace BenchApp.Controllers
{
    public class XssSafeController : Controller
    {
        [HttpGet]
        public ContentResult Label()
        {
            string label = Request.Query["label"];
            string safe = HttpUtility.HtmlEncode(label);
            return Content($"<a href='/page'>{safe}</a>", "text/html");
        }
    }
}
