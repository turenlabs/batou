using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace BenchApp.Controllers
{
    public class SqliSafeController : Controller
    {
        private readonly AppDbContext _db;

        [HttpPost]
        public IActionResult Update([FromBody] SettingDto dto)
        {
            var setting = _db.Settings.Find(dto.Id);
            if (setting != null)
            {
                setting.Value = dto.Value;
                _db.SaveChanges();
            }
            return Ok();
        }
    }
}
