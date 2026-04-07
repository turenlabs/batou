using System;
using System.Data.SqlClient;

namespace VulnerableApp.Data
{
    public class DatabaseConfig
    {
        // Vulnerable: hardcoded connection string with password
        private string connectionString = "Server=prod-db.example.com;Database=AppDB;User Id=admin;Password=P@ssw0rd123;";

        // Vulnerable: hardcoded with Pwd shorthand
        private string connStr = "Server=192.168.1.100;Database=Users;Uid=root;Pwd=hunter2;Encrypt=true;";

        public SqlConnection GetConnection()
        {
            return new SqlConnection(connectionString);
        }
    }
}
