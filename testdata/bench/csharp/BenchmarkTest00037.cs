using Microsoft.AspNetCore.Mvc;
using System.Web;

namespace BenchApp.Controllers
{
    public class XssSafeController : Controller
    {
        [HttpGet]
        public IActionResult Error()
        {
            string msg = Request.Query["error"];
            string encoded = HttpUtility.HtmlEncode(msg);
            Response.WriteAsync($"<p class='error'>{encoded}</p>");
            return new EmptyResult();
        }
    }
}
