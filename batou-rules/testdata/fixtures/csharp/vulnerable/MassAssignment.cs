using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp.Controllers
{
    public class User
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public bool IsAdmin { get; set; }
        public decimal Balance { get; set; }
    }

    public class UserController : Controller
    {
        private readonly AppDbContext _context;

        // Vulnerable: TryUpdateModelAsync without field restrictions
        // An attacker could set IsAdmin=true or Balance=999999
        [HttpPost]
        public async Task<IActionResult> Edit(int id)
        {
            var user = await _context.Users.FindAsync(id);
            await TryUpdateModelAsync<User>(user);
            await _context.SaveChangesAsync();
            return RedirectToAction("Index");
        }
    }
}
