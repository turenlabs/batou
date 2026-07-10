using Newtonsoft.Json;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserController : Controller
    {
        [HttpPost]
        public IActionResult Arrays()
        {
            string json = new StreamReader(Request.Body).ReadToEnd();
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Arrays
            };
            var obj = JsonConvert.DeserializeObject(json, settings);
            return Ok(obj);
        }
    }
}
