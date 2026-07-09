using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;

namespace BenchApp.Controllers
{
    public class SqliSafeController : Controller
    {
        [HttpGet]
        public IActionResult Login()
        {
            string user = Request.Query["username"];
            string pass = Request.Query["password"];
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM users WHERE username = @user AND password = @pass", conn);
            cmd.Parameters.AddWithValue("@user", user);
            cmd.Parameters.AddWithValue("@pass", pass);
            var reader = cmd.ExecuteReader();
            return Ok();
        }
    }
}
