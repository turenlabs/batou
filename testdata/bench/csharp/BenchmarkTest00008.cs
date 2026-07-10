using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SqliController : Controller
    {
        [HttpGet]
        public IActionResult Report()
        {
            string category = HttpContext.Request.Query["cat"];
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            string query = "SELECT COUNT(*) FROM items WHERE category = '" + category + "'";
            var cmd = new SqlCommand(query, conn);
            var count = cmd.ExecuteScalar();
            return Ok(count);
        }
    }
}
