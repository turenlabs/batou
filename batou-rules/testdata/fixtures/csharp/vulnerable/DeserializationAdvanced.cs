using System;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Soap;
using System.Web.Script.Serialization;
using System.Web.UI;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Newtonsoft.Json;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class DeserAdvancedController : ControllerBase
    {
        // Vulnerable: ObjectStateFormatter (CVE-2020-0688 Exchange RCE vector)
        [HttpPost("viewstate")]
        public IActionResult DeserializeViewState([FromBody] string data)
        {
            var formatter = new ObjectStateFormatter();
            var obj = formatter.Deserialize(data);
            return Ok(obj);
        }

        // Vulnerable: LosFormatter deserialization
        [HttpPost("los")]
        public IActionResult DeserializeLos([FromBody] string data)
        {
            var formatter = new LosFormatter();
            var obj = formatter.Deserialize(data);
            return Ok(obj);
        }

        // Vulnerable: NetDataContractSerializer
        [HttpPost("netdcs")]
        public IActionResult DeserializeNetDCS()
        {
            var serializer = new NetDataContractSerializer();
            var obj = serializer.Deserialize(Request.Body);
            return Ok(obj);
        }

        // Vulnerable: NetDataContractSerializer.ReadObject
        [HttpPost("netdcs-read")]
        public IActionResult ReadNetDCS()
        {
            var serializer = new NetDataContractSerializer();
            var obj = serializer.ReadObject(Request.Body);
            return Ok(obj);
        }

        // Vulnerable: JavaScriptSerializer with custom resolver
        [HttpPost("jsserializer")]
        public IActionResult DeserializeJSSerializer([FromBody] string json)
        {
            var serializer = new JavaScriptSerializer();
            var obj = serializer.Deserialize<object>(json);
            return Ok(obj);
        }

        // Vulnerable: DataContractJsonSerializer
        [HttpPost("dcjs")]
        public IActionResult DeserializeDCJS()
        {
            var serializer = new DataContractJsonSerializer(typeof(object));
            var obj = serializer.ReadObject(Request.Body);
            return Ok(obj);
        }

        // Vulnerable: TypeNameHandling.Auto
        [HttpPost("json-auto")]
        public IActionResult DeserializeJsonAuto([FromBody] string json)
        {
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Auto
            };
            var obj = JsonConvert.DeserializeObject(json, settings);
            return Ok(obj);
        }

        // Vulnerable: TypeNameHandling.Objects
        [HttpPost("json-objects")]
        public IActionResult DeserializeJsonObjects([FromBody] string json)
        {
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Objects
            };
            var obj = JsonConvert.DeserializeObject(json, settings);
            return Ok(obj);
        }

        // Vulnerable: Dynamic assembly loading from user input
        [HttpPost("assembly")]
        public IActionResult LoadAssembly([FromBody] string path)
        {
            var asm = Assembly.LoadFrom(path);
            return Ok(asm.GetName().Name);
        }

        // Vulnerable: Roslyn scripting with user input
        [HttpPost("script")]
        public async Task<IActionResult> EvalScript([FromBody] string code)
        {
            var result = await CSharpScript.EvaluateAsync<object>(code);
            return Ok(result);
        }

        // Vulnerable: Dynamic type instantiation from user-controlled name
        [HttpPost("activate")]
        public IActionResult ActivateType([FromBody] string typeName)
        {
            var obj = Activator.CreateInstance(Type.GetType(typeName));
            return Ok(obj);
        }
    }
}
