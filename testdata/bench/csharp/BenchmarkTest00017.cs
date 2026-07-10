using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SqliSafeController : Controller
    {
        [HttpPost]
        public IActionResult Insert([FromBody] UserDto dto)
        {
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            var cmd = new SqlCommand("INSERT INTO users (name, email) VALUES (@name, @email)", conn);
            cmd.Parameters.AddWithValue("@name", dto.Name);
            cmd.Parameters.AddWithValue("@email", dto.Email);
            cmd.ExecuteNonQuery();
            return Ok();
        }
    }
}
