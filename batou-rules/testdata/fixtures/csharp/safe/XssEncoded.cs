using System;
using System.Net;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Mvc;

namespace SafeApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SearchController : ControllerBase
    {
        // Safe: HTML-encoded output
        [HttpGet("search")]
        public async Task SearchAsync(string query)
        {
            var encoded = HtmlEncoder.Default.Encode(query);
            var html = "<html><body><h1>Results for: " + encoded + "</h1></body></html>";
            Response.ContentType = "text/html";
            await Response.WriteAsync(html);
        }

        // Safe: WebUtility.HtmlEncode
        [HttpGet("greet")]
        public IActionResult Greet(string name)
        {
            var safeName = WebUtility.HtmlEncode(name);
            return Content("<p>Hello, " + safeName + "!</p>", "text/html");
        }
    }
}
