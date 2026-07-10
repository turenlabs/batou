using Newtonsoft.Json;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserSafeController : Controller
    {
        [HttpPost]
        public IActionResult Parse()
        {
            string json = new StreamReader(Request.Body).ReadToEnd();
            var obj = JsonConvert.DeserializeObject<UserDto>(json);
            return Ok(obj);
        }
    }
}
