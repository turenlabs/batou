using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserSafeController : Controller
    {
        [HttpPost]
        public IActionResult Validate()
        {
            string json = new StreamReader(Request.Body).ReadToEnd();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            string name = root.GetProperty("name").GetString();
            return Ok(name);
        }
    }
}
