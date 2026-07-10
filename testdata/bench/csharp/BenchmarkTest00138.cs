using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class RedirectSafeController : Controller
    {
        [HttpPost]
        public IActionResult After()
        {
            return RedirectToAction("Index");
        }
    }
}
