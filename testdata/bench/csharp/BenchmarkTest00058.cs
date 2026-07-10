using Microsoft.AspNetCore.Mvc;
using System;

namespace BenchApp.Controllers
{
    public class CmdiSafeController : Controller
    {
        [HttpGet]
        public IActionResult Time()
        {
            var now = DateTime.UtcNow;
            return Ok(now.ToString("o"));
        }
    }
}
