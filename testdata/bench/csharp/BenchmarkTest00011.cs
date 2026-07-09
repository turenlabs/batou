using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SqliSafeController : Controller
    {
        [HttpGet]
        public IActionResult Search()
        {
            string input = Request.Query["name"];
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM users WHERE name = @name", conn);
            cmd.Parameters.AddWithValue("@name", input);
            var reader = cmd.ExecuteReader();
            return Ok();
        }
    }
}
