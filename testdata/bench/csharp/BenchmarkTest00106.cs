using System.IO;
using System.Runtime.Serialization;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserController : Controller
    {
        [HttpPost]
        public IActionResult NetData()
        {
            var stream = Request.Body;
            var serializer = new NetDataContractSerializer();
            var obj = serializer.Deserialize(stream);
            return Ok(obj);
        }
    }
}
