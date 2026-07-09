using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserSafeController : Controller
    {
        [HttpPost]
        public async Task<IActionResult> Stream()
        {
            var obj = await JsonSerializer.DeserializeAsync<OrderDto>(Request.Body);
            return Ok(obj);
        }
    }
}
