using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SqliSafeController : Controller
    {
        [HttpPost]
        public IActionResult Delete()
        {
            string id = Request.Form["id"];
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            var cmd = new SqlCommand("DELETE FROM orders WHERE id = @id", conn);
            cmd.Parameters.Add(new SqlParameter("@id", int.Parse(id)));
            cmd.ExecuteNonQuery();
            return Ok();
        }
    }
}
