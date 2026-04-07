using System;
using System.DirectoryServices;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class LdapController : ControllerBase
    {
        // Vulnerable: LDAP filter with string concatenation
        [HttpGet("search")]
        public IActionResult Search(string username)
        {
            var searcher = new DirectorySearcher();
            searcher.Filter = "(&(objectClass=user)(sAMAccountName=" + username + "))";
            var results = searcher.FindAll();
            return Ok(results.Count);
        }

        // Vulnerable: LDAP filter with string interpolation
        [HttpGet("find")]
        public IActionResult Find(string email)
        {
            var searcher = new DirectorySearcher($"(&(objectClass=user)(mail={email}))");
            var result = searcher.FindOne();
            return Ok(result?.Path);
        }
    }
}
