using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiController : Controller
    {
        [HttpPost]
        public IActionResult Curl()
        {
            string url = Request.Form["url"];
            Process.Start("curl", url);
            return Ok();
        }
    }
}
