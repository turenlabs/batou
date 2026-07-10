using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace BenchApp.Controllers
{
    public class SqliSafeController : Controller
    {
        private readonly AppDbContext _db;

        [HttpGet]
        public IActionResult Find()
        {
            string email = Request.Query["email"];
            var user = _db.Users.FirstOrDefault(u => u.Email == email);
            return Ok(user);
        }
    }
}
