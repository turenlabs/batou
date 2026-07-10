using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace BenchApp.Controllers
{
    public class SqliController : Controller
    {
        private readonly AppDbContext _db;

        [HttpGet]
        public IActionResult Raw()
        {
            string term = Request.Query["q"];
            var results = _db.Users.FromSqlRaw($"SELECT * FROM users WHERE email LIKE '%{term}%'");
            return Ok(results);
        }
    }
}
