using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace BenchApp.Controllers
{
    public class XssSafeController : Controller
    {
        [HttpGet]
        public ContentResult Tooltip()
        {
            string title = Request.Query["title"];
            string safe = WebUtility.HtmlEncode(title);
            return Content($"<span title='{safe}'>Hover</span>", "text/html");
        }
    }
}
