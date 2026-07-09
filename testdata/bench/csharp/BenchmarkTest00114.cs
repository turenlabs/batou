using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserSafeController : Controller
    {
        [HttpPost]
        public IActionResult WithBinder()
        {
            string json = new StreamReader(Request.Body).ReadToEnd();
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Auto,
                SerializationBinder = new KnownTypesBinder()
            };
            var obj = JsonConvert.DeserializeObject(json, settings);
            return Ok(obj);
        }
    }

    public class KnownTypesBinder : ISerializationBinder
    {
        public Type BindToType(string assemblyName, string typeName) => typeof(UserDto);
        public void BindToName(Type type, out string assemblyName, out string typeName)
        { assemblyName = null; typeName = type.Name; }
    }
}
