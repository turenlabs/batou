using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserController : Controller
    {
        [HttpPost]
        public IActionResult Load()
        {
            var stream = Request.Body;
            var formatter = new BinaryFormatter();
            var obj = formatter.Deserialize(stream);
            return Ok(obj.ToString());
        }
    }
}
