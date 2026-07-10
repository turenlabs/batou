using System.Xml.Linq;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserSafeController : Controller
    {
        [HttpPost]
        public IActionResult ParseXml()
        {
            var doc = XDocument.Load(Request.Body);
            string value = doc.Root.Element("name")?.Value;
            return Ok(value);
        }
    }
}
