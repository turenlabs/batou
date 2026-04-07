using System;
using System.Data.SqlClient;
using Microsoft.Extensions.Configuration;

namespace SafeApp.Data
{
    public class DatabaseConfig
    {
        private readonly IConfiguration _config;

        public DatabaseConfig(IConfiguration config)
        {
            _config = config;
        }

        // Safe: connection string from configuration (not hardcoded)
        public SqlConnection GetConnection()
        {
            var connectionString = _config.GetConnectionString("DefaultConnection");
            return new SqlConnection(connectionString);
        }

        // Safe: connection string from environment variable
        public SqlConnection GetConnectionFromEnv()
        {
            var connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION_STRING");
            return new SqlConnection(connectionString);
        }
    }
}
