using System;
using System.IO;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace SafeApp.Controllers
{
    public class SafeDto
    {
        public string Name { get; set; }
        public int Value { get; set; }
    }

    // Custom binder that only allows known safe types
    public class KnownTypesBinder : ISerializationBinder
    {
        public Type BindToType(string assemblyName, string typeName)
        {
            if (typeName == "SafeApp.Controllers.SafeDto")
                return typeof(SafeDto);
            throw new InvalidOperationException($"Unknown type: {typeName}");
        }

        public void BindToName(Type serializedType, out string assemblyName, out string typeName)
        {
            assemblyName = null;
            typeName = serializedType.Name;
        }
    }

    [ApiController]
    [Route("api/[controller]")]
    public class DeserAdvancedSafeController : ControllerBase
    {
        // Safe: System.Text.Json (no polymorphic deserialization by default)
        [HttpPost("system-json")]
        public IActionResult DeserializeSystemJson([FromBody] string json)
        {
            var data = System.Text.Json.JsonSerializer.Deserialize<SafeDto>(json);
            return Ok(data);
        }

        // Safe: Newtonsoft.Json with TypeNameHandling.None
        [HttpPost("newtonsoft-safe")]
        public IActionResult DeserializeNewtonsoft([FromBody] string json)
        {
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.None
            };
            var data = JsonConvert.DeserializeObject<SafeDto>(json, settings);
            return Ok(data);
        }

        // Safe: Newtonsoft.Json with custom SerializationBinder
        [HttpPost("newtonsoft-binder")]
        public IActionResult DeserializeWithBinder([FromBody] string json)
        {
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Auto,
                SerializationBinder = new KnownTypesBinder()
            };
            var data = JsonConvert.DeserializeObject<SafeDto>(json, settings);
            return Ok(data);
        }

        // Safe: Assembly loaded by strong name with PublicKeyToken verification
        [HttpPost("assembly-safe")]
        public IActionResult LoadVerifiedAssembly()
        {
            var name = new System.Reflection.AssemblyName("SafeLib, PublicKeyToken=abc123");
            var asm = System.Reflection.Assembly.Load(name);
            return Ok(asm.GetName().Name);
        }
    }
}
