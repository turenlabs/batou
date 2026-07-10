using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SqliController : Controller
    {
        [HttpPost]
        public IActionResult Update()
        {
            string value = Request.Form["value"];
            string field = Request.Form["field"];
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            var cmd = new SqlCommand("UPDATE settings SET " + field + " = '" + value + "'", conn);
            cmd.ExecuteNonQuery();
            return Ok();
        }
    }
}
