using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class XssSafeController : Controller
    {
        [HttpGet]
        public JsonResult Search()
        {
            string query = Request.Query["q"];
            return Json(new { query = query, results = new string[0] });
        }
    }
}
