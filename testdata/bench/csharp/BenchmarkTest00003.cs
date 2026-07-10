using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SqliController : Controller
    {
        [HttpGet]
        public IActionResult Filter()
        {
            string col = Request.Query["sort"];
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM products ORDER BY " + col, conn);
            var reader = cmd.ExecuteReader();
            return Ok();
        }
    }
}
