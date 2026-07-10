using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiController : Controller
    {
        [HttpGet]
        public IActionResult Ping()
        {
            string host = Request.Query["host"];
            Process.Start("cmd", "/c ping " + host);
            return Ok();
        }
    }
}
