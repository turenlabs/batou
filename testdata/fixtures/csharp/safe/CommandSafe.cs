using System;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

namespace SafeApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ToolsController : ControllerBase
    {
        // Safe: validated input with allowlist
        [HttpGet("ping")]
        public IActionResult PingHost(string host)
        {
            // Only allow valid IP addresses
            if (!Regex.IsMatch(host, @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"))
            {
                return BadRequest("Invalid IP address");
            }

            var startInfo = new ProcessStartInfo("ping")
            {
                Arguments = "-c 4 " + host,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            var process = Process.Start(startInfo);
            var result = process.StandardOutput.ReadToEnd();
            return Ok(result);
        }
    }
}
