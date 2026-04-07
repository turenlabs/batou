using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SearchController : ControllerBase
    {
        // Vulnerable: reflected XSS via Response.WriteAsync
        [HttpGet("search")]
        public async Task SearchAsync(string query)
        {
            var html = "<html><body><h1>Results for: " + query + "</h1></body></html>";
            Response.ContentType = "text/html";
            await Response.WriteAsync(html);
        }

        // Vulnerable: Html.Raw with user input in Razor
        [HttpGet("profile")]
        public IActionResult Profile(string bio)
        {
            ViewBag.UserBio = bio;
            // In the Razor view: @Html.Raw(ViewBag.UserBio)
            return View();
        }

        // Vulnerable: Response.Write with unencoded user input
        [HttpGet("greet")]
        public void Greet(string name)
        {
            Response.Write("<p>Hello, " + name + "!</p>");
        }
    }
}
