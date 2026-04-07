using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class DeserController : ControllerBase
    {
        // Vulnerable: BinaryFormatter deserialization of untrusted data
        [HttpPost("binary")]
        public IActionResult DeserializeBinary()
        {
            var formatter = new BinaryFormatter();
            var obj = formatter.Deserialize(Request.Body);
            return Ok(obj.ToString());
        }

        // Vulnerable: SoapFormatter deserialization
        [HttpPost("soap")]
        public IActionResult DeserializeSoap()
        {
            var formatter = new SoapFormatter();
            var obj = formatter.Deserialize(Request.Body);
            return Ok(obj.ToString());
        }

        // Vulnerable: JSON.NET with TypeNameHandling.All
        [HttpPost("json")]
        public IActionResult DeserializeJson([FromBody] string json)
        {
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            };
            var obj = JsonConvert.DeserializeObject(json, settings);
            return Ok(obj);
        }
    }
}
