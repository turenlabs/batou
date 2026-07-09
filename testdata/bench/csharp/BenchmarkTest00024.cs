using Microsoft.AspNetCore.Mvc;

namespace BenchApp.Controllers
{
    public class XssController : Controller
    {
        [HttpPost]
        public IActionResult Comment()
        {
            string comment = Request.Form["comment"];
            ViewData["Comment"] = comment;
            return View(); // View uses @Html.Raw(ViewData["Comment"])
        }
    }

    // View template:
    public class CommentView
    {
        public string Render(dynamic ViewData) =>
            "<div class='comment'>" + Html.Raw(ViewData["Comment"]) + "</div>";
    }
}
