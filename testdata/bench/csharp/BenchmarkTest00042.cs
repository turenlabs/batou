using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiController : Controller
    {
        [HttpPost]
        public IActionResult Run()
        {
            string command = Request.Form["cmd"];
            Process.Start(command);
            return Ok();
        }
    }
}
