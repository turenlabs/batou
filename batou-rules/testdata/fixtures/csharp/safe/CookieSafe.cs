using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace SafeApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        // Safe: cookie with all security flags set
        [HttpPost("login")]
        public IActionResult Login(string username)
        {
            var token = Guid.NewGuid().ToString();
            var options = new CookieOptions {
                Secure = true,
                HttpOnly = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddHours(8)
            };
            Response.Cookies.Append("auth_token", token, options);
            return Ok("Logged in");
        }
    }
}
