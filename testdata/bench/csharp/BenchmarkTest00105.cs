using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserController : Controller
    {
        [HttpPost]
        public IActionResult Session()
        {
            byte[] data = Convert.FromBase64String(Request.Form["session"]);
            var stream = new MemoryStream(data);
            var formatter = new BinaryFormatter();
            var state = formatter.Deserialize(stream);
            return Ok();
        }
    }
}
