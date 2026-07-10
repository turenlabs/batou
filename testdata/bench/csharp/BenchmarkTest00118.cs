using Newtonsoft.Json;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserSafeController : Controller
    {
        [HttpPost]
        public IActionResult List()
        {
            string json = new StreamReader(Request.Body).ReadToEnd();
            var items = JsonConvert.DeserializeObject<List<ItemDto>>(json);
            return Ok(items);
        }
    }
}
