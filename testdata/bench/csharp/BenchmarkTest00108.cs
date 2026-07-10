using System.Xml.Serialization;
using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserController : Controller
    {
        [HttpPost]
        public IActionResult XmlType()
        {
            string typeName = Request.Form["type"];
            string xml = new StreamReader(Request.Body).ReadToEnd();
            var serializer = new XmlSerializer(Type.GetType(typeName));
            var reader = new StringReader(xml);
            var obj = serializer.Deserialize(reader);
            return Ok(obj);
        }
    }
}
