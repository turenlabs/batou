using System;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ToolsController : ControllerBase
    {
        // Vulnerable: user input passed to Process.Start
        [HttpGet("ping")]
        public IActionResult PingHost(string host)
        {
            var output = Process.Start("ping", host);
            return Ok(output);
        }

        // Vulnerable: user input in ProcessStartInfo
        [HttpPost("execute")]
        public IActionResult RunCommand([FromBody] string command)
        {
            var startInfo = new ProcessStartInfo("cmd.exe")
            {
                Arguments = "/c " + command,
                RedirectStandardOutput = true
            };
            var process = new Process { StartInfo = startInfo };
            process.Start();
            var result = process.StandardOutput.ReadToEnd();
            return Ok(result);
        }
    }
}
