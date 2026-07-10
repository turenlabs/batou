using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SqliController : Controller
    {
        [HttpGet]
        public IActionResult Login()
        {
            string user = Request.Query["username"];
            string pass = Request.Query["password"];
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            string sql = "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + pass + "'";
            var cmd = new SqlCommand(sql, conn);
            var reader = cmd.ExecuteReader();
            return Ok();
        }
    }
}
