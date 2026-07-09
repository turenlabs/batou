using Microsoft.AspNetCore.Mvc;
using System.Web;

namespace BenchApp.Controllers
{
    public class XssSafeController : Controller
    {
        [HttpGet]
        public IActionResult Echo()
        {
            string input = Request.Query["msg"];
            string safe = HttpUtility.HtmlEncode(input);
            Response.WriteAsync("<html><body>" + safe + "</body></html>");
            return new EmptyResult();
        }
    }
}
