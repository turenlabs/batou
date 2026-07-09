using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserSafeController : Controller
    {
        [HttpPost]
        public IActionResult ModelBind([FromBody] UserDto dto)
        {
            return Ok(dto);
        }
    }
}
