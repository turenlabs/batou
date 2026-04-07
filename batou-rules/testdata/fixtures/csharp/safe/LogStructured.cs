using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Safe.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class LogController : ControllerBase
    {
        private readonly ILogger<LogController> _logger;

        public LogController(ILogger<LogController> logger)
        {
            _logger = logger;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] string username)
        {
            // Safe: structured logging with template placeholders
            _logger.LogInformation("Login attempt for user: {Username}", username);
            _logger.LogWarning("Failed login for: {Username}", username);
            return Ok();
        }
    }
}
