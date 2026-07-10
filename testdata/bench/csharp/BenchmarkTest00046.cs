using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiController : Controller
    {
        [HttpPost]
        public IActionResult Script()
        {
            string script = Request.Form["script"];
            Process.Start("/bin/bash", "-c " + script);
            return Ok();
        }
    }
}
