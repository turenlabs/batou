using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SqliSafeController : Controller
    {
        [HttpGet]
        public IActionResult GetById()
        {
            string rawId = Request.Query["id"];
            int id = int.Parse(rawId);
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
            cmd.Parameters.AddWithValue("@id", id);
            return Ok();
        }
    }
}
