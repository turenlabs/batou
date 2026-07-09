using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Collections.Generic;

namespace BenchApp.Controllers
{
    public class SqliSafeController : Controller
    {
        private static readonly HashSet<string> AllowedColumns = new() { "name", "date", "price" };

        [HttpGet]
        public IActionResult Sort()
        {
            string col = Request.Query["sort"];
            if (!AllowedColumns.Contains(col)) col = "name";
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            var cmd = new SqlCommand($"SELECT * FROM products ORDER BY {col}", conn);
            var reader = cmd.ExecuteReader();
            return Ok();
        }
    }
}
