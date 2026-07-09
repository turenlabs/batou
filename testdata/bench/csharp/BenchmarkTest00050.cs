using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiController : Controller
    {
        [HttpPost]
        public IActionResult Exec()
        {
            string args = Request.Form["args"];
            Process.Start("cmd", "/c dir " + args);
            return Ok();
        }
    }
}
