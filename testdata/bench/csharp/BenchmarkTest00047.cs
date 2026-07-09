using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiController : Controller
    {
        [HttpGet]
        public IActionResult Whois()
        {
            string ip = Request.Query["ip"];
            var proc = new Process();
            proc.StartInfo.FileName = "whois";
            proc.StartInfo.Arguments = ip;
            proc.Start();
            return Ok();
        }
    }
}
