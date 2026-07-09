using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace BenchApp.Controllers
{
    public class XssSafeController : Controller
    {
        private readonly HtmlEncoder _encoder;

        public XssSafeController(HtmlEncoder encoder) { _encoder = encoder; }

        [HttpGet]
        public ContentResult Comment()
        {
            string comment = Request.Query["comment"];
            string safe = _encoder.Encode(comment);
            return Content($"<div>{safe}</div>", "text/html");
        }
    }
}
