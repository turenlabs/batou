using System;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace SafeApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly string _connectionString;

        public UsersController(AppDbContext context)
        {
            _context = context;
            _connectionString = "Server=localhost;Database=mydb;";
        }

        // Safe: parameterized query with SqlParameter
        [HttpGet("search")]
        public IActionResult SearchUsers(string name)
        {
            using var connection = new SqlConnection(_connectionString);
            connection.Open();
            using var command = new SqlCommand("SELECT * FROM Users WHERE Name = @name", connection);
            command.Parameters.AddWithValue("@name", name);
            var reader = command.ExecuteReader();
            return Ok(reader);
        }

        // Safe: FromSqlInterpolated (auto-parameterized)
        [HttpGet("find")]
        public IActionResult FindUser(string email)
        {
            var users = _context.Users
                .FromSqlInterpolated($"SELECT * FROM Users WHERE Email = {email}")
                .ToList();
            return Ok(users);
        }

        // Safe: ExecuteSqlInterpolated
        [HttpPost("delete")]
        public IActionResult DeleteUser(int userId)
        {
            _context.Database.ExecuteSqlInterpolated($"DELETE FROM Users WHERE Id = {userId}");
            return Ok();
        }
    }
}
