using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace VulnerableApp
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // Vulnerable: AllowAnyOrigin with AllowCredentials
            services.AddCors(options =>
            {
                options.AddPolicy("DangerousPolicy", builder =>
                {
                    builder.AllowAnyOrigin()
                           .AllowCredentials()
                           .AllowAnyMethod()
                           .AllowAnyHeader();
                });
            });
        }
    }
}
