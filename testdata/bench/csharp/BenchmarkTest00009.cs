using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
using System;

namespace BenchApp.Controllers
{
    public class SqliController : Controller
    {
        [HttpPost]
        public IActionResult Insert()
        {
            string name = Request.Form["name"];
            string email = Request.Form["email"];
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            var sql = String.Format("INSERT INTO users (name, email) VALUES ('{0}', '{1}')", name, email);
            var cmd = new SqlCommand(sql, conn);
            cmd.ExecuteNonQuery();
            return Ok();
        }
    }
}
