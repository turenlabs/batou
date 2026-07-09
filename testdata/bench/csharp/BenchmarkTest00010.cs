using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SqliController : Controller
    {
        [HttpGet]
        public IActionResult Search()
        {
            string keyword = Request.Query["keyword"];
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            string query = "SELECT * FROM articles WHERE title LIKE '%" + keyword + "%'";
            var cmd = new SqlCommand(query, conn);
            var reader = cmd.ExecuteReader();
            return Ok();
        }
    }
}
