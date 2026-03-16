// Source: CWE-89 - SQL Injection via string concatenation in C#
// Expected: BATOU-CS
// OWASP: A03:2021 - Injection (SQL Injection)

using System;
using System.Data.SqlClient;

namespace App
{
    class UserRepository
    {
        public void FindUser(string username)
        {
            var conn = new SqlConnection("Server=localhost;Database=app;");
            var query = "SELECT * FROM users WHERE name = '" + username + "'";
            var cmd = new SqlCommand(query, conn);
            conn.Open();
            var reader = cmd.ExecuteReader();
        }

        static void Main(string[] args)
        {
            var repo = new UserRepository();
            repo.FindUser(args[0]);
        }
    }
}
