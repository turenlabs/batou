using Newtonsoft.Json;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserController : Controller
    {
        [HttpPost]
        public IActionResult Config()
        {
            string json = new StreamReader(Request.Body).ReadToEnd();
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Auto
            };
            var obj = JsonConvert.DeserializeObject<object>(json, settings);
            return Ok(obj);
        }
    }
}
