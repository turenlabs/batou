using System.Xml.Serialization;
using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserSafeController : Controller
    {
        [HttpPost]
        public IActionResult Xml()
        {
            var serializer = new XmlSerializer(typeof(UserDto));
            var reader = new StreamReader(Request.Body);
            var obj = (UserDto)serializer.Deserialize(reader);
            return Ok(obj);
        }
    }
}
