using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SqliSafeController : Controller
    {
        [HttpGet]
        public IActionResult Search()
        {
            string keyword = Request.Query["keyword"];
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM articles WHERE title LIKE @pattern", conn);
            cmd.Parameters.AddWithValue("@pattern", "%" + keyword + "%");
            return Ok();
        }
    }
}
