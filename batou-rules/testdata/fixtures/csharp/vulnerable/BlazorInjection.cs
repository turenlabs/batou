using System;
using System.Net.Mail;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp.Components
{
    // Vulnerable: Blazor component with unvalidated parameter used in SQL
    public class UserProfile : ComponentBase
    {
        [Parameter]
        public string UserId { get; set; }

        [SupplyParameterFromQuery]
        public string SearchTerm { get; set; }

        [Inject]
        public NavigationManager Navigation { get; set; }

        protected override void OnInitialized()
        {
            // Vulnerable: using NavigationManager.Uri directly
            var uri = NavigationManager.Uri;
            var host = new Uri(uri).Host;
        }
    }

    // Vulnerable: Host header used in password reset link
    [ApiController]
    [Route("api/[controller]")]
    public class PasswordResetController : ControllerBase
    {
        [HttpPost("reset")]
        public IActionResult SendReset([FromBody] string email)
        {
            // Vulnerable: Host header injection in password reset
            var host = Request.Host;
            var resetLink = $"https://{host}/reset?token=abc123";

            var client = new SmtpClient("mail.example.com");
            var message = new MailMessage("noreply@example.com", email,
                "Password Reset", $"Click here: {resetLink}");
            client.Send(message);

            return Ok();
        }
    }

    // Vulnerable: Dynamic LINQ expression from user input
    public class SearchController : ControllerBase
    {
        [HttpGet("search")]
        public IActionResult Search([FromQuery] string filter)
        {
            // Vulnerable: DynamicExpression.Parse with user input
            var expr = System.Linq.Dynamic.Core.DynamicExpressionParser.ParseLambda(
                typeof(object), null, filter);
            return Ok(expr);
        }
    }
}
