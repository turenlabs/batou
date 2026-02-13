using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        // Vulnerable: cookie without Secure, HttpOnly, or SameSite flags
        [HttpPost("login")]
        public IActionResult Login(string username)
        {
            var token = GenerateToken(username);
            var options = new CookieOptions {
                Expires = DateTimeOffset.UtcNow.AddHours(8)
            };
            Response.Cookies.Append("auth_token", token, options);
            return Ok("Logged in");
        }

        private string GenerateToken(string username) => Guid.NewGuid().ToString();
    }
}
