using System.IO;
using System.Web.UI;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class DeserController : Controller
    {
        [HttpPost]
        public IActionResult ViewState()
        {
            string data = Request.Form["viewstate"];
            var formatter = new LosFormatter();
            var obj = formatter.Deserialize(data);
            return Ok();
        }
    }
}
