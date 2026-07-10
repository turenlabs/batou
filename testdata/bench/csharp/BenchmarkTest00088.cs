using System.Net;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class SsrfController : Controller
    {
        [HttpPost]
        public IActionResult FetchPage()
        {
            string url = Request.Form["pageUrl"];
            var client = new WebClient();
            byte[] data = client.DownloadData(url);
            return File(data, "text/html");
        }
    }
}
