using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Vulnerable.Controllers
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
        public IActionResult Login(string username)
        {
            // Vulnerable: user input directly concatenated into log message
            _logger.LogInformation("Login attempt for user: " + username);
            _logger.LogWarning("Failed login for: " + username);
            return Ok();
        }
    }
}
