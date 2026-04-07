using System;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace VulnerableApp.Controllers
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

        // Vulnerable: string concatenation in SqlCommand
        [HttpGet("search")]
        public IActionResult SearchUsers(string name)
        {
            var query = "SELECT * FROM Users WHERE Name = '" + name + "'";
            using var connection = new SqlConnection(_connectionString);
            connection.Open();
            using var command = new SqlCommand(query, connection);
            var reader = command.ExecuteReader();
            return Ok(reader);
        }

        // Vulnerable: string interpolation in FromSqlRaw
        [HttpGet("find")]
        public IActionResult FindUser(string email)
        {
            var sql = $"SELECT * FROM Users WHERE Email = '{email}'";
            var users = _context.Users.FromSqlRaw(sql).ToList();
            return Ok(users);
        }

        // Vulnerable: ExecuteSqlRaw with user input
        [HttpPost("delete")]
        public IActionResult DeleteUser(string userId)
        {
            var sql = "DELETE FROM Users WHERE Id = " + userId;
            _context.Database.ExecuteSqlRaw(sql);
            return Ok();
        }
    }
}
