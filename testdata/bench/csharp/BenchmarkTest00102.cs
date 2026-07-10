using System.IO;
using System.Runtime.Serialization.Formatters.Soap;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserController : Controller
    {
        [HttpPost]
        public IActionResult LoadSoap()
        {
            var stream = Request.Body;
            var formatter = new SoapFormatter();
            var obj = formatter.Deserialize(stream);
            return Ok(obj.ToString());
        }
    }
}
