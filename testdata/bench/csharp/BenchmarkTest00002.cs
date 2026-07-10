using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SqliController : Controller
    {
        [HttpPost]
        public IActionResult Delete()
        {
            string id = Request.Form["id"];
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            string query = $"DELETE FROM orders WHERE id = {id}";
            var cmd = new SqlCommand(query, conn);
            cmd.ExecuteNonQuery();
            return Ok();
        }
    }
}
