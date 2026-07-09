using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class CmdiSafeController : Controller
    {
        [HttpPost]
        public IActionResult Resize([FromBody] ImageDto dto)
        {
            int width = dto.Width;
            int height = dto.Height;
            var psi = new ProcessStartInfo("convert", $"-resize {width}x{height} input.jpg output.jpg");
            psi.UseShellExecute = false;
            Process.Start(psi);
            return Ok();
        }
    }
}
