using System;
using System.IO;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace SafeApp.Controllers
{
    public class DataDto
    {
        public string Name { get; set; }
        public int Value { get; set; }
    }

    [ApiController]
    [Route("api/[controller]")]
    public class DeserController : ControllerBase
    {
        // Safe: System.Text.Json with known type (no type discriminator)
        [HttpPost("json")]
        public IActionResult DeserializeJson([FromBody] string json)
        {
            var data = JsonSerializer.Deserialize<DataDto>(json);
            return Ok(data);
        }

        // Safe: Newtonsoft.Json with TypeNameHandling.None
        [HttpPost("newtonsoft")]
        public IActionResult DeserializeNewtonsoft([FromBody] string json)
        {
            var settings = new Newtonsoft.Json.JsonSerializerSettings
            {
                TypeNameHandling = Newtonsoft.Json.TypeNameHandling.None
            };
            var data = Newtonsoft.Json.JsonConvert.DeserializeObject<DataDto>(json, settings);
            return Ok(data);
        }
    }
}
