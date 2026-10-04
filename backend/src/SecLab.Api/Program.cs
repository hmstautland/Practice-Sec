using Microsoft.EntityFrameworkCore;
using SecLab.Api.Data;
using SecLab.Api.Endpoints;
using System.Security.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Apply modern TSL 
builder.WebHost.ConfigureKestrel(k => 
    k.ConfigureHttpsDefaults(o => 
        o.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13));

builder.Services.AddHsts(o => {
    o.MaxAge = TimeSpan.FromDays(365);
    o.IncludeSubDomains = true;
    o.Preload = true;
});


builder.Services.AddDbContext<AppDbContext>(o => o.UseSqlServer(builder.Configuration.GetConnectionString("Default")));
// WEAKNESS: wide-open CORS.
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();

if(!app.Environment.IsDevelopment())
{
    app.UseHsts();
    app.UseHttpsRedirection();
}

// WEAKNESS: developer exception page always on (leaks stack traces), plain HTTP only.
app.UseDeveloperExceptionPage();
app.UseCors();
app.UseStaticFiles();

using (var scope = app.Services.CreateScope())
    Seed.Run(scope.ServiceProvider.GetRequiredService<AppDbContext>());

Api.Map(app);
app.Run();

public partial class Program;
