using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace SafeApp
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // Safe: CORS with explicit origin list
            services.AddCors(options =>
            {
                options.AddPolicy("SecurePolicy", builder =>
                {
                    builder.WithOrigins("https://app.example.com", "https://admin.example.com")
                           .AllowCredentials()
                           .WithMethods("GET", "POST")
                           .WithHeaders("Authorization", "Content-Type");
                });
            });
        }
    }
}
