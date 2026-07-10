using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace BenchApp.Controllers
{
    public class SqliController : Controller
    {
        private readonly AppDbContext _db;

        [HttpPost]
        public IActionResult Execute()
        {
            string table = Request.Form["table"];
            _db.Database.ExecuteSqlRaw($"DROP TABLE IF EXISTS {table}");
            return Ok();
        }
    }
}
