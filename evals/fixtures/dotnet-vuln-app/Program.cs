using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;

public class Program
{
    public static void Main(string[] args)
    {
        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(web => web.UseStartup<Startup>());
}

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllersWithViews();
        services.AddCors(o => o.AddPolicy("AnyOrigin", p => p
            .AllowAnyOrigin()
            .AllowCredentials()));
        services.AddControllers()
            .AddNewtonsoftJson(o =>
                o.SerializerSettings.TypeNameHandling = TypeNameHandling.All);
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseDeveloperExceptionPage();
        app.UseCors("AnyOrigin");
        app.UseRouting();
        app.UseEndpoints(e => e.MapDefaultControllerRoute());
    }
}
